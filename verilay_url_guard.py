"""
verilay_url_guard.py — SSRF protection for Verilay's live-URL scanner.

Verilay fetches URLs that a stranger typed into a box. Without this, that box
is a request-forgery primitive: the attacker picks the URL, Verilay's server
makes the request from inside its own network, and the response comes back to
the attacker rendered in the report.

Three holes this closes in the original `fetch_url()`:

  1. NO DNS RESOLUTION. `169.254.169.254` was blocked as a literal string, but
     a hostname resolving to it was not. `http://metadata.attacker.com/` where
     that name has an A record of 169.254.169.254 sailed straight through — and
     169.254.169.254 is the cloud metadata endpoint, which on many hosts serves
     instance credentials.

  2. REDIRECTS WERE FOLLOWED BLIND. `requests.get()` defaults to
     allow_redirects=True. A perfectly innocent public URL returning
     `302 Location: http://169.254.169.254/latest/meta-data/` was followed
     without any of the checks being re-run. Validating only the first URL is
     the single most common way SSRF protection is defeated.

  3. THE JS BUNDLE FETCHES HAD NO CHECKS AT ALL. `fetch_url()` parses
     `<script src=...>` out of the fetched HTML and fetches up to 3 of them
     with a bare `requests.get`. Those URLs come from the attacker's own page.
     `<script src="http://169.254.169.254/latest/meta-data/iam/">` and the
     contents land in the report. This was the widest of the three.

Stdlib plus `requests`, which Verilay already has.

Residual risk, stated honestly: this resolves the hostname and then makes the
request, so a DNS entry that changes between those two moments (DNS rebinding)
is not fully closed. Closing it requires pinning the socket to the validated
IP, which breaks SNI and virtual hosting. For a tool that fetches public web
apps, per-hop validation plus a short timeout is the right trade — but do not
describe this as airtight.
"""

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

# `requests` is imported lazily inside safe_get() so that validate_url() can be
# imported and unit-tested anywhere, with no third-party dependency at all.

# ── Policy ─────────────────────────────────────────────────────────────────────

ALLOWED_SCHEMES = ("http", "https")

# Deployed web apps live on 80/443. Anything else is far more likely to be
# someone probing an internal service than a real Lovable or Replit deployment.
# Widen this only if real users hit it.
ALLOWED_PORTS = {80, 443, 8080, 8443}

MAX_REDIRECTS = 3

# Ranges Python's is_private does not always cover, or that are worth naming
# explicitly so the intent is readable.
EXTRA_BLOCKED = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("169.254.0.0/16"),   # link-local — cloud metadata lives here
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


class BlockedURL(ValueError):
    """Raised when a URL fails the safety check. Message is user-facing."""


# ── IP checks ──────────────────────────────────────────────────────────────────

def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    # ::ffff:127.0.0.1 is loopback in practice but Python's IPv6Address flags
    # say otherwise — unwrap the mapped v4 address and judge that instead.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return True

    return any(ip in net for net in EXTRA_BLOCKED if ip.version == net.version)


def _resolve(host: str) -> List[ipaddress._BaseAddress]:
    """Every address this hostname resolves to. A literal IP resolves to itself."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise BlockedURL(
            "That address could not be found. Check the URL and try again."
        )

    out = []
    for info in infos:
        addr = info[4][0]
        try:
            out.append(ipaddress.ip_address(addr.split("%")[0]))  # strip zone id
        except ValueError:
            continue
    if not out:
        raise BlockedURL("That address could not be resolved.")
    return out


# ── URL validation ─────────────────────────────────────────────────────────────

def validate_url(url: str) -> Tuple[str, List[ipaddress._BaseAddress]]:
    """
    Check a URL is safe to fetch. Returns (hostname, resolved_ips).
    Raises BlockedURL with a message suitable for showing to a user.

    EVERY address the name resolves to must pass. A hostname with one public
    and one private A record is a deliberate attack, not a misconfiguration.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise BlockedURL("Only http:// and https:// addresses can be scanned.")

    host = parsed.hostname
    if not host:
        raise BlockedURL("That does not look like a complete web address.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise BlockedURL(
            f"Port {port} cannot be scanned — only standard web ports are allowed. "
            "If your app is public, use its normal https:// address."
        )

    ips = _resolve(host)
    for ip in ips:
        if _is_blocked_ip(ip):
            # Deliberately vague. Confirming which internal addresses exist
            # would itself be useful reconnaissance.
            raise BlockedURL(
                "That address points to a private or internal network, so it "
                "cannot be scanned. Use a public URL, or analyse the GitHub "
                "repository or a ZIP export instead."
            )

    return host, ips


# ── Safe fetching ──────────────────────────────────────────────────────────────

def safe_get(url: str, timeout: int = 25, headers: dict = None,
             max_redirects: int = MAX_REDIRECTS,
             verify: bool = True):
    """
    Drop-in replacement for requests.get() for any user-influenced URL.
    Returns a requests.Response.

    Redirects are followed MANUALLY so that every hop is validated. This is the
    part that matters: validating only the URL the user typed is the standard
    way SSRF filters get bypassed.
    """
    import requests

    current = url
    for _ in range(max_redirects + 1):
        validate_url(current)

        resp = requests.get(
            current,
            timeout=timeout,
            headers=headers or {},
            allow_redirects=False,      # non-negotiable — we follow them ourselves
            verify=verify,
            stream=False,
        )

        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp

        location = resp.headers.get("Location")
        if not location:
            return resp

        current = urljoin(current, location)   # handles relative redirects

    raise BlockedURL(
        "That address redirected too many times. It may be misconfigured or "
        "deliberately looping."
    )
