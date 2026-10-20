"""verilay_livecheck.py - what a LIVE-ADDRESS scan can honestly tell a visitor (2026-10-20).

A live-address scan only sees what a browser is sent. Since 19 Oct 2026 it is always an ungraded "Preview". The first real
visitor got a page with no findings and no layers, and ran it twice. This module fills the gap with things that really can be
told from outside, plus tests the visitor can run themselves:

  * facts read from the response (no AI, same answer every time): which security headers the main page sends, and which
    outside sites its scripts come from;
  * what the preview did and did not look at, in plain words;
  * "Check it yourself" tests that suit a live site (log out, two accounts, view source, apostrophe, typed HTML, wrong passwords);
  * the next step for a real review: a GitHub link or a ZIP.

Rules it follows:
  * Only facts are stored in the report (header names, script hosts). All wording is fixed text kept here.
  * A header that is not seen is "not seen", never "a vulnerability": hosts may add headers elsewhere and not every app needs all.
  * Never raises. Missing or odd input gives no panel for that part, never an error.
  * Every value from the report is escaped when drawn.
"""
import re
from html import escape
from urllib.parse import urlparse

import verilay_selfcheck as selfcheck

LIVE_CHECK_IDS = ["logged_out", "two_accounts", "key_in_browser", "odd_characters", "typed_html", "too_many_tries"]

# (header, what it does, in plain words)
HEADERS = (
    ("Strict-Transport-Security", "Tells browsers to always use the secure (https) version of your site."),
    ("Content-Security-Policy", "Limits which scripts and files your page may load, which makes it harder to slip in malicious code."),
    ("X-Frame-Options", "Stops other sites from showing your page inside a hidden frame (a trick called clickjacking)."),
    ("X-Content-Type-Options", "Stops browsers from guessing what kind of file something is, which can turn a harmless file into code."),
    ("Referrer-Policy", "Controls how much of your page's address is shared when someone clicks a link to another site."),
    ("Permissions-Policy", "Switches off browser features your page doesn't need, such as the camera or location."),
)

HEADER_NOTE = ("Not seeing a header isn't always a problem. Some hosts add them in another place, and not every site needs all of them. "
               "This reads the response to the main page only.")
SCRIPTS_NOTE = ("This is normal for analytics, fonts or chat widgets. Check that you recognise each one, because a script from another "
                "site runs with full access to your page.")
LIMITS = ("your source code, your server or backend, your database rules, how login really works, and settings that live in a dashboard")
NEXT_STEP = ("For a real review of your code, choose a GitHub link or a ZIP upload on the home page. A ZIP keeps your project private: it is read "
             "while the scan runs and is not saved.")

_HEADER_LINE = re.compile(r"^([A-Za-z-]{3,64}):\s*(.*)$")
_SCRIPT_SRC = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)


def build(files, live_url=""):
    """Facts read from a live-address scan's files. Small, plain data; safe to store. Never raises."""
    try:
        files = files if isinstance(files, dict) else {}
        present = {}
        for line in str(files.get("_headers.txt", "")).splitlines():
            m = _HEADER_LINE.match(line.strip())
            if m and not line.upper().startswith("HTTP SECURITY"):
                present[m.group(1).lower()] = m.group(2)
        headers = {name: (name.lower() in present) for name, _ in HEADERS}
        csp = present.get("content-security-policy", "")
        host = (urlparse(str(live_url)).hostname or "").lower()
        hosts = []
        for src in _SCRIPT_SRC.findall(str(files.get("index.html", ""))):
            src = src.strip()
            if src.startswith("//"):
                src = "https:" + src
            if not src.lower().startswith(("http://", "https://")):
                continue
            h = (urlparse(src).hostname or "").lower()
            if h and h != host and not h.endswith("." + host) and h not in hosts:
                hosts.append(h)
        return {
            "https": str(live_url).lower().startswith("https://"),
            "headers": headers,
            "frame_ancestors_in_csp": "frame-ancestors" in csp.lower(),
            "external_script_hosts": hosts[:8],
        }
    except Exception:
        return {}


def served_count(files_analysed=None, fallback=None):
    """How many files the site really sent. Verilay's own note files (named with a leading underscore, such as _headers.txt and
    _meta.txt) are not the site's, so they are not counted. Falls back to the stored total when the names are not known."""
    try:
        if isinstance(files_analysed, list) and files_analysed:
            return len([n for n in files_analysed if isinstance(n, str) and not n.startswith("_")])
        return int(fallback) if isinstance(fallback, int) and not isinstance(fallback, bool) else None
    except Exception:
        return None


def _usable(live):
    return isinstance(live, dict) and isinstance(live.get("headers"), dict)


def view(live):
    """Plain data for the page and the browser script: the facts joined to their fixed wording. Never raises."""
    try:
        out = {"has_facts": _usable(live), "headers": None, "scripts": None, "https": None, "limits": LIMITS,
               "header_note": HEADER_NOTE, "scripts_note": SCRIPTS_NOTE, "next_step": NEXT_STEP,
               "check_detail": selfcheck.detail(LIVE_CHECK_IDS), "safety": selfcheck.SAFETY}
        if _usable(live):
            rows = []
            for name, plain in HEADERS:
                sent = bool(live["headers"].get(name))
                covered = (name == "X-Frame-Options" and not sent and bool(live.get("frame_ancestors_in_csp")))
                rows.append({"name": name, "sent": sent, "covered": covered, "plain": plain})
            out["headers"] = rows
            hosts = live.get("external_script_hosts")
            out["scripts"] = [str(h) for h in hosts if isinstance(h, str)][:8] if isinstance(hosts, list) else None
            out["https"] = bool(live.get("https"))
        return out
    except Exception:
        return {"has_facts": False, "headers": None, "scripts": None, "https": None, "limits": LIMITS, "header_note": HEADER_NOTE,
                "scripts_note": SCRIPTS_NOTE, "next_step": NEXT_STEP, "check_detail": [], "safety": selfcheck.SAFETY}


def _card_title(text):
    return f'<div class="st">{escape(text)}</div>'


def render_html(live, files_read=None):
    """The saved report page's live-address panels, as HTML ('' on any problem). The page supplies the escaped data it already has."""
    try:
        v = view(live)
        parts = []
        n = f"{int(files_read)} file{'' if int(files_read) == 1 else 's'}" if isinstance(files_read, int) and files_read > 0 else "the files"
        parts.append(_card_title("What this preview looked at") +
                     '<div class="card"><div style="font-size:13px;color:#444;line-height:1.6">'
                     f'Verilay read the page your browser receives from this address, plus its script files ({escape(n)} in all). '
                     'It ran fixed checks on them for exposed keys and passwords and for weak hashing patterns, and read the security '
                     'headers and outside scripts shown below.</div>'
                     f'<div style="font-size:13px;color:#444;line-height:1.6;margin-top:.5rem"><strong>It can\'t see</strong> {escape(v["limits"])}. '
                     'So &ldquo;not graded&rdquo; means &ldquo;not enough to grade&rdquo;, not &ldquo;fine&rdquo;.</div></div>')
        if v["headers"] is not None:
            rows = []
            for r in v["headers"]:
                if r["sent"]:
                    mark, colour, word = "&#10003;", "#1D9E75", "sent"
                elif r["covered"]:
                    mark, colour, word = "&#10003;", "#1D9E75", "covered by the Content-Security-Policy"
                else:
                    mark, colour, word = "&ndash;", "#92400E", "not seen"
                rows.append(f'<div style="padding:.45rem 0;border-top:0.5px solid #eee"><span style="font-family:monospace;font-size:12.5px">{escape(r["name"])}</span> '
                            f'<span style="color:{colour};font-size:12.5px;font-weight:600">{mark} {escape(word)}</span>'
                            f'<div style="font-size:12.5px;color:#666">{escape(r["plain"])}</div></div>')
            https = ('<div style="font-size:13px;color:#444;margin-bottom:.4rem">This address uses a secure (https) connection.</div>'
                     if v["https"] else
                     '<div style="font-size:13px;color:#92400E;margin-bottom:.4rem">This address does not use a secure (https) connection.</div>')
            parts.append(_card_title("Security headers this site sends") + '<div class="card">' + https + "".join(rows) +
                         f'<div style="font-size:12px;color:#6b6966;margin-top:.5rem">{escape(v["header_note"])}</div></div>')
        if v["scripts"] is not None:
            if v["scripts"]:
                items = ", ".join(f'<span style="font-family:monospace;font-size:12.5px">{escape(h)}</span>' for h in v["scripts"])
                body = (f'<div style="font-size:13px;color:#444;line-height:1.6">The main page loads scripts from other sites: {items}.</div>'
                        f'<div style="font-size:12px;color:#6b6966;margin-top:.4rem">{escape(v["scripts_note"])}</div>')
            else:
                body = '<div style="font-size:13px;color:#444">The main page loads no scripts from other sites.</div>'
            parts.append(_card_title("Outside scripts this page loads") + '<div class="card">' + body + "</div>")
        tests = selfcheck.render(LIVE_CHECK_IDS)
        parts.append(_card_title("Check it yourself on your live site") +
                     '<div class="card"><div style="font-size:13px;color:#444;line-height:1.6">These are the tests a scanner can\'t do from outside. '
                     f'Try them on your own site.</div>{tests}</div>')
        parts.append(_card_title("Want a real review?") +
                     f'<div class="card"><div style="font-size:13px;color:#444;line-height:1.6">{escape(v["next_step"])}</div>'
                     '<a href="/" style="display:inline-block;margin-top:.6rem;font-size:13px;color:#534AB7;font-weight:600;text-decoration:none">'
                     'Run a review of your code &rarr;</a> '
                     '<a href="/privacy" style="font-size:12px;color:#6b6966;margin-left:8px">What we keep</a></div>')
        return "".join(parts)
    except Exception:
        return ""
