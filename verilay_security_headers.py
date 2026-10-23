"""verilay_security_headers.py - the browser-protection headers every Verilay page should send, and /.well-known/security.txt (23 Oct 2026).

Why: an outside scanner gave verilay.dev a D, and 0 of 22 on headers, because the site sent none of them. A security tool should not be the
house with no lock on the door. The headers are cheap and none of them can break a normal page:

  Strict-Transport-Security   the browser only ever uses https for verilay.dev (sent only on https requests)
  X-Content-Type-Options      the browser does not guess a file's type, which blocks a classic upload trick
  X-Frame-Options + CSP frame-ancestors   no other site may put Verilay inside a frame (clickjacking)
  Referrer-Policy             other sites see only that the visitor came from verilay.dev, not which report page
  Permissions-Policy          the page cannot ask for the camera, microphone, location or payment screen
  Content-Security-Policy     ONLY the parts that cannot break a page: no framing, no <base> tag tricks, no plugins
  Cross-Origin-Opener-Policy  another window cannot reach into Verilay's window
  Cross-Origin-Resource-Policy  other sites cannot load Verilay's PAGES or data as if they were their own resources (a leak route).
                              Only on HTML and JSON: images such as the badge and the checked-app stamp are MEANT to be shown on other sites.

NOT included, on purpose: a Content-Security-Policy that limits scripts and styles. Verilay's pages carry their scripts and styles inline,
so a strict policy would need a large rewrite (or "unsafe-inline", which protects little). That is a separate piece of work.
A route that sets one of these headers itself keeps its own value (setdefault).
"""
from datetime import datetime, timedelta, timezone

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
}
CORP = "same-origin"
CORP_TYPES = ("text/html", "application/json")      # pages and data only; images, badges and stamps stay embeddable on other sites
HSTS = "max-age=15552000"          # 180 days; no includeSubDomains and no preload until Moses decides to commit to that
SECURITY_CONTACT = "mailto:moses@verilay.dev"
POLICY_URL = "https://github.com/ekbm/verilay/blob/main/SECURITY.md"
CANONICAL = "https://verilay.dev/.well-known/security.txt"
EXPIRES_DAYS = 180


def _is_https(request):
    proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    return proto == "https" or bool(getattr(request, "is_secure", False))


def security_txt(now=None):
    """The text of /.well-known/security.txt (RFC 9116). Expires is always about six months ahead, so the file never goes stale."""
    exp = (now or datetime.now(timezone.utc)) + timedelta(days=EXPIRES_DAYS)
    return ("Contact: " + SECURITY_CONTACT + "\n"
            "Expires: " + exp.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n"
            "Preferred-Languages: en\n"
            "Canonical: " + CANONICAL + "\n"
            "Policy: " + POLICY_URL + "\n")


def init(app):
    from flask import request, Response

    @app.after_request
    def _add_security_headers(resp):
        for name, value in HEADERS.items():
            resp.headers.setdefault(name, value)
        if (resp.mimetype or "") in CORP_TYPES:
            resp.headers.setdefault("Cross-Origin-Resource-Policy", CORP)
        if _is_https(request):
            resp.headers.setdefault("Strict-Transport-Security", HSTS)
        return resp

    @app.route("/.well-known/security.txt")
    def _security_txt():
        r = Response(security_txt(), mimetype="text/plain")
        r.headers["Cache-Control"] = "public, max-age=3600"
        return r
