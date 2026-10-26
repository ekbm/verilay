#!/usr/bin/env python3
"""
Verilay — the paid path: pricing page, checkout, webhook, sign-in, account.

Kept in its own module and registered as a Blueprint so app.py stays the free
tool it has always been. Nothing in here runs for an anonymous visitor doing a
free analysis.

Read `entitlement_for_request` first if you are changing anything — it is the
single place that decides whether someone is allowed a deep scan, and every route
that matters goes through it.

© 2026 Moses Ekbote.
"""

import json
import os
import re
import threading
import time
import urllib.parse

from flask import (Blueprint, request, redirect, jsonify, session,
                   render_template_string, Response)

import verilay_billing as billing
import verilay_accounts as accounts
import verilay_deepscan as deepscan
import verilay_notify as notify

bp = Blueprint("paywall", __name__)

# Filled in by init() so this module never imports app.py — that would be a
# circular import, since app.py imports this.
_deps = {"sb": None, "get_ip": lambda: "unknown", "get_report_data": lambda _i: None}


def init(app, sb=None, get_ip=None, get_report_data=None):
    """Wire the blueprint into the app. Call once, from app.py."""
    _deps["sb"] = sb
    if get_ip:
        _deps["get_ip"] = get_ip
    if get_report_data:
        _deps["get_report_data"] = get_report_data
    app.register_blueprint(bp)
    return bp


def _sb():
    return _deps["sb"]


# ── Shared page shell ──────────────────────────────────────────────────────────
# Matches the existing /privacy, /terms and /about pages rather than inventing a
# second visual language.
_NAV_LOGO = (
    '<svg width="24" height="24" viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg" '
    'style="flex-shrink:0;vertical-align:middle"><rect width="400" height="400" rx="88" fill="#534AB7"/>'
    '<circle cx="200" cy="200" r="112" fill="#ffffff" fill-opacity="0.12"/>'
    '<circle cx="200" cy="200" r="86" fill="#ffffff" fill-opacity="0.12"/>'
    '<path d="M140 142 L200 268 L260 142" fill="none" stroke="#ffffff" stroke-width="28" '
    'stroke-linecap="round" stroke-linejoin="round"/><path d="M122 142 L278 142" fill="none" '
    'stroke="#ffffff" stroke-width="28" stroke-linecap="round"/></svg>'
)

_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__ - Verilay</title>
<meta name="robots" content="__ROBOTS__">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
h1{font-size:26px;font-weight:700;margin-bottom:.5rem}
h2{font-size:17px;font-weight:600;margin:1.5rem 0 .5rem}
p{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px}
ul{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px;padding-left:1.25rem}
li{margin-bottom:.35rem}
.card{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1.25rem;margin-bottom:1rem}
.eyebrow{font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem}
label{display:block;font-size:13px;font-weight:600;margin-bottom:.35rem}
input[type=text],input[type=email],select,textarea{width:100%;padding:10px 12px;font-size:15px;border:1px solid #e8e6e0;border-radius:8px;background:#fff;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:#534AB7}
.btn{display:inline-block;border:none;cursor:pointer;font-family:inherit;font-size:14px;font-weight:600;padding:11px 22px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none}
.btn:disabled{background:#c9c7c2;cursor:not-allowed}
.btn-quiet{background:#fff;color:#4a4846;border:1px solid #e8e6e0}
.note{font-size:13px;color:#6b6966;line-height:1.6}
.err{background:#FCEBEB;color:#A32D2D;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:1rem}
.ok{background:#E1F5EE;color:#085041;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:1rem}
.warn{background:#FAEEDA;color:#633806;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:1rem}
.price{font-size:34px;font-weight:700;letter-spacing:-0.02em}
.row{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.6rem 0;border-bottom:0.5px solid #f0efec;font-size:14px}
.row:last-child{border-bottom:none}
.row>span:first-child{min-width:0;overflow-wrap:break-word;word-break:break-word}
.tag{font-size:11px;font-weight:600;padding:3px 9px;border-radius:20px;background:#E1F5EE;color:#085041}
.tag-off{background:#f0efec;color:#6b6966}
a{color:#534AB7}
/* Collapsible account sections (2026-09-15) — native <details>, no JS. Each
   summary is a full-width tap target so this reads as three plain buttons on
   a phone, not a dense wall of cards. */
details.acc{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;margin-bottom:1rem;overflow:hidden}
details.acc>summary{list-style:none;cursor:pointer;padding:1rem 1.25rem;font-weight:600;font-size:15px;display:flex;justify-content:space-between;align-items:center;gap:.75rem;-webkit-tap-highlight-color:transparent}
details.acc>summary::-webkit-details-marker{display:none}
details.acc>summary::after{content:'+';font-size:20px;font-weight:400;color:#6b6966;flex-shrink:0}
details.acc[open]>summary::after{content:'\\2212'}
details.acc>summary:focus-visible{outline:2px solid #534AB7;outline-offset:-2px}
details.acc[open]>summary{border-bottom:0.5px solid #e8e6e0}
details.acc .acc-body{padding:1rem 1.25rem}
details.acc .acc-body>.card{margin-bottom:0}
@media(max-width:480px){
  .wrap{padding:1.5rem 1rem}
  details.acc>summary{padding:.85rem 1rem;font-size:14px}
  details.acc .acc-body{padding:.85rem 1rem}
}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917">__LOGO__ <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <span style="font-size:13px">__NAVRIGHT__</span>
</nav>
<div class="wrap">
__BODY__
</div>
</body>
</html>"""


def _page(title, body, robots="index,follow"):
    user = accounts.current_user()
    if user:
        admin_link = ('<a href="/admin" style="color:#534AB7;text-decoration:none;font-weight:600">Admin</a> &nbsp;'
                      if _is_admin_user(user) else "")
        right = (f'{admin_link}<a href="/account" style="color:#6b6966;text-decoration:none">{_esc(user["email"])}</a>'
                 f' &nbsp;<a href="/logout" style="color:#6b6966;text-decoration:none">Sign out</a>')
    else:
        right = '<a href="/" style="color:#6b6966;text-decoration:none">Back to app</a>'
    html = (_SHELL.replace("__TITLE__", title)
                  .replace("__ROBOTS__", robots)
                  .replace("__LOGO__", _NAV_LOGO)
                  .replace("__NAVRIGHT__", right)
                  .replace("__BODY__", body))
    return Response(html, mimetype="text/html")


def _esc(s):
    """Escape for HTML. Everything user-supplied on these pages goes through it —
    emails and repo names both come from outside."""
    return (str(s or "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# ── Who is allowed a deep scan ─────────────────────────────────────────────────
def entitlement_for_request(repo):
    """The purchase entitling this visitor to deep-scan `repo`, or None.

    Three ways to be entitled, and the difference matters:

    1. Signed in. The email is proven — they clicked a link or typed a code we
       emailed — so they get every purchase made with that address.

    2. Just paid, not yet signed in. `paid_sid` is set only after asking Stripe
       whether that Checkout Session was really paid, and it grants access to THAT
       purchase alone.

    3. Signed in AND on the ADMIN_EMAILS allowlist — a synthetic entitlement,
       no real purchase row, so Moses can test the live paid product without
       paying $19 each time. Still requires the real sign-in flow (proof of
       inbox access), same as path 1 — only the PAYMENT step is skipped, not
       authentication.

    Why not simply trust the email Stripe collected and sign them straight in?
    Because Stripe does not verify it. Someone could check out with a stranger's
    address and, if that were enough to be "signed in", would then see the
    stranger's reports. Paying proves you paid; it does not prove who you are.
    """
    canonical = billing.normalise_repo(repo)
    if not canonical:
        return None

    user = accounts.current_user()
    if user:
        row = billing.active_purchase_for(_sb(), user["email"], canonical)
        if row:
            return row
        if user["email"].strip().lower() in billing.ADMIN_EMAILS:
            return {
                "id": f"admin-bypass-{canonical}",
                "email": user["email"],
                "repo": canonical,
                "status": "active",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "scans_used": 0,
            }

    if session.get("paid_sid") and session.get("paid_repo") == canonical:
        row = billing.active_purchase_for(_sb(), session.get("paid_email", ""), canonical)
        if row:
            return row
    return None


# ── Pricing / entry point ──────────────────────────────────────────────────────
_WHAT_YOU_GET = """
  <h2>Free analysis vs. the deep scan</h2>
  <div style="overflow-x:auto">
  <table style="width:100%;min-width:480px;border-collapse:collapse;margin-bottom:.75rem">
    <tr style="border-bottom:0.5px solid #e8e6e0">
      <th style="text-align:left;padding:6px 8px 6px 0"></th>
      <th style="text-align:left;padding:6px 8px;font-size:12px;color:#6b6966;font-weight:600">Free</th>
      <th style="text-align:left;padding:6px 0;font-size:12px;color:#6b6966;font-weight:600">Deep scan</th>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Files read</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">25 — the ones most likely to matter</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">150 — 6&times; more of your code</td>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Dependency vulnerabilities</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">Number and severity only</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">Exact package, version, and CVE for each</td>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Fix guidance</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">Up to 8 prompts to investigate with your AI builder</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">A ready-to-paste fix for every vulnerable package, plus one prompt to update them all</td>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Who can see your data (Supabase apps)</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">A count of the problems found</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">Each one listed in plain English, with a fix</td>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Similar apps</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">The closest open-source match</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">Up to 6 similar projects to learn from or partner with, with what each is best at (free GitHub repos only, not commercial apps)</td>
    </tr>
    <tr style="border-bottom:0.5px solid #f0efec">
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Checking a fix worked</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">Run a fresh analysis (may sample different files)</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">Unlimited re-scans of the same app for 30 days</td>
    </tr>
    <tr>
      <td style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917">Reports saved</td>
      <td style="padding:8px 8px;font-size:13px;color:#4a4846">Via your share link</td>
      <td style="padding:8px 0;font-size:13px;color:#4a4846">In your account</td>
    </tr>
  </table>
  </div>
  <p class="note">The free analysis is not going away and is not getting worse.
  Every file is still checked for exposed keys, free, for everyone. Paying adds
  depth — it never removes anything.</p>
"""


_TD = 'style="padding:8px 8px;font-size:13px;color:#4a4846;vertical-align:top"'
_TDL = 'style="padding:8px 8px 8px 0;font-size:13px;color:#1a1917;vertical-align:top"'
_TH = 'style="text-align:left;padding:6px 8px;font-size:12px;color:#6b6966;font-weight:600"'


def _row(label, free, pro, deep):
    return (f'<tr style="border-bottom:0.5px solid #f0efec"><td {_TDL}>{label}</td><td {_TD}>{free}</td>'
            f'<td {_TD}>{pro}</td><td {_TD}>{deep}</td></tr>')


_WHAT_YOU_GET_3 = (
    '<h2 id="compare">Free, Pro and Deep</h2><div style="overflow-x:auto">'
    '<table style="width:100%;min-width:560px;border-collapse:collapse;margin-bottom:.75rem">'
    f'<tr style="border-bottom:0.5px solid #e8e6e0"><th {_TH}></th><th {_TH}>Free</th>'
    f'<th {_TH}>Pro<br><span style="font-weight:400">free during the launch (until 30 Nov), then A$4.99 a scan</span></th><th {_TH}>Deep scan</th></tr>'
    + _row("Files read", "Up to 25, the ones most likely to matter", "Up to 50", "Up to 150")
    + _row("The six areas (login, settings, data, API, pages, packages)", "Short plain-English notes", "Full explanations",
           "Full explanations, every file read")
    + _row("Exposed keys, risky packages, who can see your data", "Checked", "Checked", "Checked, with each package and its fix")
    + _row("Fix prompts for your AI builder", "One, for the most serious problem", "<strong>One for every finding</strong>",
           "One for every finding, plus one prompt to update every package")
    + _row("Similar apps", "The closest open-source match", "The closest open-source match",
           "Up to 6 to learn from or partner with")
    + _row("Checking a fix worked", "3 free scans a day", "One free Pro scan per email during the launch; then pay per scan",
           "Re-scans of the same app for 30 days")
    + _row("Best for", "A quick health check", "Fixing what the free scan found", "Before launch, or a full review")
    + '</table></div>'
    '<p class="note">The free analysis stays free: every file is still checked for exposed keys, risky packages and who can '
    'see your data, and you get a fix prompt for the most serious problem. Pro adds a ready-to-paste fix prompt for every '
    'finding. During the launch, Pro is free: answer 4 quick questions after a free scan to unlock one Pro scan.</p>'
)


def _compare_html():
    """The comparison on the pricing page: Free | Pro | Deep once the light free scan is switched on, else the original."""
    return _WHAT_YOU_GET_3 if "haiku" in (os.getenv("VERILAY_FREE_MODEL", "") or "") else _WHAT_YOU_GET


_DEEP_STYLE = """
<style>
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.75rem;margin:.5rem 0 1rem}
.dcard{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem}
.dcard h3{font-size:14px;font-weight:600;margin-bottom:.35rem;color:#1a1917}
.dcard p{font-size:13px;margin:0}
.dcard.star{border-color:#534AB7;background:#faf9ff}
.dcard .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#3C3489;background:#EEEDFE;border-radius:20px;padding:2px 8px;margin-bottom:.4rem}
.dsteps{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.75rem;margin:.5rem 0 1rem}
.dstep{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem}
.dstep .n{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;background:#534AB7;color:#fff;font-size:12px;font-weight:700;margin-bottom:.45rem}
.dstep h3{font-size:14px;font-weight:600;margin-bottom:.25rem}
.dstep p{font-size:13px;margin:0}
.dfit{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.75rem;margin:.5rem 0 1rem}
.dfit .card{margin:0}
.dfit h3{font-size:14px;font-weight:600;margin-bottom:.4rem}
.dfit ul{margin:0;padding-left:1.1rem;font-size:13px}
details.faq{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;margin-bottom:.5rem}
details.faq>summary{cursor:pointer;padding:.8rem 1rem;font-size:14px;font-weight:600;list-style:none;display:flex;justify-content:space-between;gap:.75rem}
details.faq>summary::-webkit-details-marker{display:none}
details.faq>summary::after{content:'+';font-weight:400;color:#6b6966}
details.faq[open]>summary::after{content:'\\2212'}
details.faq>p{padding:0 1rem .8rem;margin:0;font-size:13px}
.promise{background:#EEEDFE;border-radius:10px;padding:.9rem 1rem;margin:0 0 1rem}
.promise p{margin:0;font-size:13px;color:#3C3489}
.heroactions{display:flex;flex-wrap:wrap;align-items:center;gap:.75rem;margin:.25rem 0 1.25rem}
</style>
"""

_DEEP_BENEFITS = """
  <h2>What you get for the price</h2>
  <div class="dgrid">
    <div class="dcard star">
      <span class="badge">Most useful</span>
      <h3>A fix list, in the right order</h3>
      <p>The problems that matter most come first. Each one has a plain-English
      explanation of why it matters and a ready-to-paste prompt for your AI
      builder, with a Copy button. You don't need to understand the code to act on it.</p>
    </div>
    <div class="dcard">
      <h3>Every risky package, named</h3>
      <p>Your app is built on dozens or hundreds of packages written by other
      people. The report names each one that has a known weakness, with its exact
      version and vulnerability ID, plus one prompt per package and one prompt to
      update them all.</p>
    </div>
    <div class="dcard">
      <h3>Who can see your data? (Supabase apps)</h3>
      <p>Verilay reads your database rules and backend functions and lists, in
      plain English, where anyone on the internet could read or change something
      they shouldn't, with a fix for each. The free scan only shows a count.
      (Settings changed only in the Supabase dashboard can't be seen from your files.)</p>
    </div>
    <div class="dcard star">
      <span class="badge">Only in the deep scan</span>
      <h3>Similar projects to learn from or partner with</h3>
      <p>Up to 6 free, open-source projects that do something like your app. Each one
      comes with why it's similar, what it's best at, its licence and when it was last
      updated, so you can see what already exists, borrow good ideas, build on it, or get
      in touch with the people behind it about working together. (Check a project's
      licence before reusing any of its code.) These are free GitHub projects only, not
      commercial apps, so no match never means nothing similar exists.</p>
    </div>
    <div class="dcard">
      <h3>6&times; more of your code read</h3>
      <p>150 files instead of 25, so less of your app is left unchecked. If
      Verilay couldn't read part of your app, the report says so instead of showing
      a green tick. (If your app has fewer than 25 files, the free scan already
      reads all of it.)</p>
    </div>
    <div class="dcard">
      <h3>Re-scan to prove it's fixed</h3>
      <p>After you fix something, scan the same app again as often as you like for
      30 days and watch the problem disappear. Every report is saved in your account.</p>
    </div>
  </div>
"""

_DEEP_HOW = """
  <h2>How it works</h2>
  <div class="dsteps">
    <div class="dstep"><span class="n">1</span><h3>Paste your GitHub address</h3>
      <p>Public repositories only for now.</p></div>
    <div class="dstep"><span class="n">2</span><h3>Pay once</h3>
      <p>Stripe handles payment on its own page. Verilay never sees your card.</p></div>
    <div class="dstep"><span class="n">3</span><h3>Get your report</h3>
      <p>Most scans take a few minutes; bigger apps take longer. Close the tab if you
      like: the report is saved to your account and we email you when it's ready.</p></div>
  </div>
"""

_DEEP_FIT = """
  <h2>Is it right for you?</h2>
  <div class="dfit">
    <div class="card">
      <h3>A good fit if&hellip;</h3>
      <ul>
        <li>You built your app with Lovable, Bolt, Replit, Cursor, v0 or a similar tool</li>
        <li>You're about to launch, take payments or collect customer details</li>
        <li>Your app has more than a handful of files</li>
        <li>You want fixes you can paste, not a lecture</li>
      </ul>
    </div>
    <div class="card">
      <h3>Not for you if&hellip;</h3>
      <ul>
        <li>Your repository is private (public GitHub repositories only, for now; you can <a href="/private-repos">register interest in private repositories</a>)</li>
        <li>You need a human security audit or a penetration test; this is an automated first pass</li>
        <li>Your app has fewer than 25 files: the free scan already reads every file, so you'd mainly add the package details and similar projects</li>
      </ul>
    </div>
  </div>
"""

_DEEP_FAQ = """
  <h2>Questions</h2>
  <details class="faq"><summary>Will Verilay change my app or my GitHub?</summary>
    <p>No. It only reads your public repository and never writes to it. You decide
    which fixes to apply, using your own AI builder.</p></details>
  <details class="faq"><summary>Is this a security audit?</summary>
    <p>No. It's a thorough automated first pass written for non-developers. AI findings
    can vary between runs and it can miss things. See the
    <a href="/terms">terms</a> and the <a href="/ai-disclaimer">AI disclaimer</a>.</p></details>
  <details class="faq"><summary>Do I need to be technical?</summary>
    <p>No. Every finding is explained in plain English, and the fixes are written as
    prompts you paste into your AI builder.</p></details>
  <details class="faq"><summary>Can I scan more than one app?</summary>
    <p>A deep scan is tied to one repository, including its re-scans. Another app needs
    its own deep scan.</p></details>
  <details class="faq"><summary>What if the scan doesn't work?</summary>
    <p>If a deep scan fails to run or produces no usable report, you get a full refund.
    See the <a href="/terms">terms</a>.</p></details>
"""


def _sample_report_html():
    """Links to real example reports, only when the owner has chosen them (Railway variables):
    VERILAY_SAMPLE_REPORT_ID = a saved DEEP scan report, VERILAY_SAMPLE_FREE_REPORT_ID = a saved FREE report of the
    SAME app (both 12 hex characters), VERILAY_SAMPLE_REPORT_LABEL = a short line saying what the example is.
    With both, the page shows them side by side so a visitor can see the difference. Nothing is shown until set:
    no made-up example."""
    import re as _re
    def _ok(name):
        v = os.getenv(name, "").strip().lower()
        return v if _re.fullmatch(r"[0-9a-f]{12}", v) else ""
    deep, free = _ok("VERILAY_SAMPLE_REPORT_ID"), _ok("VERILAY_SAMPLE_FREE_REPORT_ID")
    if not deep:
        return ""
    click = "onclick=\"try{if(window.plausible)plausible('Sample Report Click')}catch(e){}\""
    label = os.getenv("VERILAY_SAMPLE_REPORT_LABEL", "").strip()[:240]
    note = ('<span class="note" style="display:block;margin-top:.25rem">Example: ' + _esc(label) + '</span>') if label else ""
    deep_a = ('<a href="/report/' + deep + '" target="_blank" rel="noopener" ' + click +
              ' style="font-size:14px;font-weight:600">See a real deep scan report &rarr;</a>')
    if not free:
        return deep_a + note
    free_a = ('<a href="/report/' + free + '" target="_blank" rel="noopener" ' + click +
              ' style="font-size:14px;font-weight:600">Free scan report &rarr;</a>')
    return ('<span style="display:block"><strong style="font-size:13px">See the difference on the same app:</strong> '
            + free_a + ' &nbsp;&middot;&nbsp; ' + deep_a.replace("See a real deep scan report", "Deep scan report") + '</span>' + note)


def _public_repo_error(canonical):
    """None when a deep scan of this repo may go ahead; otherwise the message to show. A deep scan reads
    GitHub with Verilay's own token, so it may only read repositories GitHub reports as public."""
    from verilay_repo_access import repo_visibility, DEEP_SCAN_PUBLIC_ONLY, UNKNOWN
    owner, _, name = canonical.partition("/")
    vis = repo_visibility(owner, name)
    if vis == "public":
        return None
    return UNKNOWN if vis == "unknown" else DEEP_SCAN_PUBLIC_ONLY


def _is_admin_user(user):
    """True for a SIGNED-IN user whose email is on the ADMIN_EMAILS list. Signing in proves the inbox, so
    only the payment step is skipped for them, never the authentication."""
    try:
        return bool(user and user.get("email") and user["email"].strip().lower() in billing.ADMIN_EMAILS)
    except Exception:
        return False


@bp.route("/deep-scan")
def deep_scan_landing():
    cancelled = request.args.get("cancelled")
    err = request.args.get("err", "")[:200]
    price = billing.price_label()

    if not billing.PAYWALL_ENABLED:
        body = f"""
  <div class="eyebrow">Coming soon</div>
  <h1>The deep scan</h1>
  <p>A one-off, deeper review of your app for {_esc(price)} plus applicable tax
  — not on sale yet. It is being built, and it will not go on sale before it works.</p>
  {_compare_html()}
  <div class="card">
    <h2 style="margin-top:0">Want to know when it opens?</h2>
    <p class="note">Leave your email on the homepage after running a free analysis
    and you will be first to hear.</p>
    <a class="btn" href="/">Run a free analysis</a>
  </div>
"""
        return _page("Deep scan", body)

    notice = ""
    if cancelled:
        notice = ('<div class="warn">Checkout cancelled — nothing was charged. '
                  'The free analysis is still there whenever you want it.</div>')
    if err:
        notice += f'<div class="err">{_esc(err)}</div>'

    admin = _is_admin_user(accounts.current_user())
    btn_label = "Start deep scan (admin: no payment)" if admin else "Continue to payment"
    admin_line = ('<p class="note" style="margin:.5rem 0 1rem;color:#3C3489">Signed in as admin: this skips payment '
                  'and goes straight to the scan.</p>' if admin else "")
    # The "Checkout Start" funnel event is for real buyers; an admin starting a scan is not one.
    funnel_script = "" if admin else """
  <script>
  // Funnel event: someone submitted the form on their way to Stripe.
  (function() {{
    var f = document.querySelector('form[action="/checkout"]');
    if (f) f.addEventListener('submit', function() {{
      try {{ if (window.plausible) plausible('Checkout Start'); }} catch (e) {{}}
    }});
  }})();
  </script>"""
    sample = _sample_report_html()
    body = f"""
  {_DEEP_STYLE}
  {notice}
  <div class="eyebrow">The deep scan &middot; one-off payment</div>
  <h1>Know what's really inside your app before you launch</h1>
  <p style="font-size:15px">You built it with an AI tool, so you didn't write the code and nobody has
  checked it. The deep scan reads up to 150 of your files, names every risky package, shows who can see
  your data if you use Supabase, finds similar projects you can learn from or partner with, and gives you
  fixes you can paste straight into Lovable, Replit, Cursor or Bolt.</p>
  <div class="price">{_esc(price)}</div>
  <p class="note" style="margin-top:-.5rem">plus applicable tax, calculated at checkout for your location.
  One payment, no subscription, and re-scans of the same app for 30 days are included.</p>
  <div class="heroactions"><a class="btn" href="#start">Start my deep scan</a> {sample}</div>
  {_DEEP_BENEFITS}
  {_compare_html()}
  {_DEEP_HOW}
  {_DEEP_FIT}
  <div class="promise"><p><strong>Honest by design.</strong> We build apps with AI tools too, and we run
  Verilay on our own apps first. If part of your app couldn't be read, the report says so. And if a
  deep scan fails to run or gives no usable report, you get a full refund.</p></div>
  <div class="card" id="start">
    <form method="POST" action="/checkout">
      <label for="repo">Which app?</label>
      <input type="text" id="repo" name="repo" placeholder="github.com/you/your-app"
             autocomplete="off" autocapitalize="none" spellcheck="false" required>
      <p class="note" style="margin:.5rem 0 1rem">
        A deep scan is tied to one repository, so we need its address. It must be
        a public GitHub repo. Re-scans of this same app are included.
      </p>
      {admin_line}
      <button class="btn" type="submit">{btn_label}</button>
    </form>
  </div>
  <p class="note">Payment is handled by Stripe on their own page — Verilay never
  sees your card. Already bought one?
  <a href="/login">Sign in</a>.</p>
  <p class="note">Want your app checked every week? <a href="/monitoring">Register interest in monitoring</a>.</p>
  {_DEEP_FAQ}
  {funnel_script}
  <p class="note">Not a penetration test. See the
  <a href="/terms">terms</a> and the <a href="/ai-disclaimer">AI disclaimer</a> for
  what this is and is not.</p>
"""
    return _page("Deep scan", body)


@bp.route("/checkout", methods=["POST"])
def checkout():
    repo = request.form.get("repo", "")
    email = (request.form.get("email", "") or "").strip().lower()
    user = accounts.current_user()
    if user:
        email = user["email"]
    # Admin (signed in, on ADMIN_EMAILS): no payment. The /deep/<repo> page grants the admin entitlement,
    # exactly as the "Deep re-scan" link on the account page already does. An unreadable repo falls through
    # to the normal flow, which refuses it.
    if _is_admin_user(user):
        canonical = billing.normalise_repo(repo)
        if canonical:
            return redirect(f"/deep/{canonical}", code=303)
    # Nobody is charged for a repository that cannot be scanned: the admin is exempt (their own repos), everyone
    # else must point at a PUBLIC repository.
    if not _is_admin_user(user):
        _canon = billing.normalise_repo(repo)
        if _canon:
            _err = _public_repo_error(_canon)
            if _err:
                return redirect(f"/deep-scan?err={_url_q(_err)}")
    try:
        url = billing.create_checkout_session(
            repo, email=email or None, client_ip=_deps["get_ip"]()
        )
    except billing.BillingError as e:
        return redirect(f"/deep-scan?err={_url_q(str(e))}")
    except Exception as e:
        print(f"[paywall] Unexpected checkout error: {e}", flush=True)
        return redirect("/deep-scan?err=Something+went+wrong+starting+checkout.")
    # 303 so the browser switches to GET on the redirect.
    return redirect(url, code=303)


def _url_q(s):
    from urllib.parse import quote_plus
    return quote_plus(s[:200])


@bp.route("/checkout/success")
def checkout_success():
    sid = request.args.get("session_id", "")[:200]
    s = billing.retrieve_paid_session(sid)
    if not s:
        body = """
  <h1>We could not confirm that payment</h1>
  <p>If you were charged, nothing is lost — email
  <a href="mailto:moses@verilay.dev">moses@verilay.dev</a> and it will be sorted
  out the same day. If you were not charged, you can
  <a href="/deep-scan">start again</a>.</p>
"""
        return _page("Payment", body, robots="noindex")

    fields = billing._session_fields(s)
    email, repo = fields["email"], fields["repo"]

    # Access to this one purchase, immediately, without claiming to know who they
    # are. See entitlement_for_request for why these are different things.
    session["paid_sid"] = s.get("id")
    session["paid_repo"] = repo
    session["paid_email"] = email
    session.permanent = True

    # The webhook is what records the purchase, and it usually arrives before the
    # browser does — but not always. Record it here too if it is missing, using
    # the session id as the idempotency key so the webhook's later insert is
    # recognised as the duplicate it is.
    if repo and email and not billing.active_purchase_for(_sb(), email, repo):
        try:
            billing.record_purchase(_sb(), s, f"success_page:{s.get('id')}")
        except Exception as e:
            print(f"[paywall] Success-page fallback record failed: {e}", flush=True)

    deep_url = f"/deep/{_esc(repo)}" if repo else "/account"
    body = f"""
  <div class="ok">Payment received. Thank you — genuinely.</div>
  <h1>Your deep scan of {_esc(repo)}</h1>
  <p>You can start it now. Re-scans of this same app are included for the next 30
  days, so fix something and run it again as often as you need.</p>
  <p><a class="btn" href="{deep_url}">Start the deep scan</a></p>

  <div class="card" style="margin-top:2rem">
    <h2 style="margin-top:0">Keep your reports — set up your account</h2>
    <p>Your reports are saved against <strong>{_esc(email)}</strong>. To reach them
    from any device, and to be sure you never lose the link, sign in once. No
    password — we email you a link.</p>
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="/account">
      <input type="email" name="email" value="{_esc(email)}" required>
      <p class="note" style="margin:.5rem 0 1rem">We will send a sign-in link to
      this address.</p>
      <button class="btn" type="submit">Email me a sign-in link</button>
    </form>
  </div>
  <p class="note">A receipt has been emailed to you by Stripe.</p>
  <script>
  // Conversion event, once per browser session (a refresh must not count twice).
  try {{
    if (window.plausible && !sessionStorage.getItem('vl_purchase_tracked')) {{
      sessionStorage.setItem('vl_purchase_tracked', '1');
      plausible('Purchase');
    }}
  }} catch (e) {{}}
  </script>
"""
    return _page("Payment received", body, robots="noindex")


# ── Webhook ────────────────────────────────────────────────────────────────────
@bp.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    """Stripe tells us a payment succeeded. This is the record of truth.

    Returns 200 for anything we understood, even if we chose to ignore it —
    a non-200 makes Stripe retry, and retrying an event we deliberately skipped
    achieves nothing. Genuine failures return 500 so the retry is useful.
    """
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = billing.verify_webhook(payload, sig)
    except billing.BadSignature as e:
        # Do not log the payload — an unsigned request is untrusted input.
        print(f"[webhook] Rejected: {e}", flush=True)
        return jsonify({"error": "invalid signature"}), 400
    except billing.BillingError as e:
        # Signed by Stripe but we could not read it — our bug, so 500 to keep the
        # retries coming rather than quietly losing a real payment.
        print(f"[webhook] Signed but unreadable: {e}", flush=True)
        return jsonify({"error": "could not read event"}), 500

    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    eid = event.get("id", "")

    try:
        if etype == "checkout.session.completed":
            if obj.get("payment_status") != "paid":
                print(f"[webhook] {eid} completed but unpaid — ignored.", flush=True)
                return jsonify({"ok": True, "ignored": "unpaid"})
            billing.record_purchase(_sb(), obj, eid)

        elif etype == "checkout.session.async_payment_succeeded":
            billing.record_purchase(_sb(), obj, eid)

        elif etype in ("charge.refunded", "charge.dispute.created"):
            _revoke_for_payment_intent(obj.get("payment_intent"), etype)

        else:
            return jsonify({"ok": True, "ignored": etype})

    except Exception as e:
        # 500 asks Stripe to try again — right for a database blip, and the event
        # stays visible as failed in the dashboard rather than disappearing.
        print(f"[webhook] Handler failed for {etype} {eid}: {e}", flush=True)
        return jsonify({"error": "handler failed"}), 500

    return jsonify({"ok": True})


def _revoke_for_payment_intent(payment_intent, reason):
    """A refunded or disputed purchase stops being an entitlement."""
    sb = _sb()
    if sb is None or not payment_intent:
        return
    status = "refunded" if reason == "charge.refunded" else "disputed"
    try:
        sb.table("purchases").update({"status": status}) \
          .eq("stripe_payment_intent", payment_intent).execute()
        print(f"[webhook] Marked purchase {payment_intent} as {status}", flush=True)
    except Exception as e:
        print(f"[webhook] Could not mark {payment_intent} {status}: {e}", flush=True)


# ── Sign in ────────────────────────────────────────────────────────────────────
@bp.route("/login", methods=["GET", "POST"])
def login():
    if accounts.current_user() and request.method == "GET":
        return redirect("/account")

    nxt = _safe_next(request.values.get("next", "/account"))
    sent_to = ""
    notice = ""

    if request.method == "POST":
        email = (request.form.get("email", "") or "").strip().lower()
        ok, msg = accounts.send_login_email(
            email, ip=_deps["get_ip"](), base_url=billing.BASE_URL
        )
        if ok:
            sent_to = email
            # The emailed link lands on /auth/callback; this browser goes back to where sign-in started (for example the
            # private-repository step). Another device lands on the account page.
            session["login_next"] = nxt
            if request.form.get("optin_features") == "yes":        # unticked by default (private-repo sign-in box)
                sb = _sb()
                if sb is not None:
                    try:
                        sb.table("waitlist").insert({"email": email, "analyses_count": 0, "source": "verilay-features"}).execute()
                    except Exception as e:
                        print(f"[login] feature opt-in not stored (a duplicate is fine): {e}", flush=True)
            notice = f'<div class="ok">{_esc(msg)}</div>'
        else:
            notice = f'<div class="err">{_esc(msg)}</div>'

    if sent_to:
        body = f"""
  {notice}
  <h1>Check your email</h1>
  <p>We sent a sign-in link to <strong>{_esc(sent_to)}</strong>. Click it and you
  are in. Open it on the device where you want to be signed in.</p>
  <p class="note">The link works only once, and expires after a short time. Nothing arrived? Check spam, then
  <a href="/login">request another</a>.</p>
"""
        return _page("Check your email", body, robots="noindex")

    body = f"""
  {notice}
  <h1>Sign in</h1>
  <p>Accounts are for deep scans and private-repository scans. A free analysis of public code or a ZIP needs
  no account. There is no password: we email you a link.</p>
  <div class="card">
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="{_esc(nxt)}">
      <label for="email">Your email</label>
      <input type="email" id="email" name="email" placeholder="you@example.com"
             autocomplete="email" required>
      <p class="note" style="margin:.5rem 0 1rem">Use the same address you paid with.</p>
      <button class="btn" type="submit">Email me a sign-in link</button>
    </form>
  </div>
"""
    return _page("Sign in", body, robots="noindex")


def _safe_next(value):
    """Only ever redirect within this site.

    An open redirect on a sign-in page is how phishing links get to look genuine:
    /login?next=https://evil.example sends someone who trusts verilay.dev
    somewhere else at the exact moment they are being asked to prove who they are.
    """
    v = (value or "").strip()
    if not v.startswith("/") or v.startswith("//") or "\\" in v:
        return "/account"
    return v[:300]


@bp.route("/auth/code", methods=["POST"])
def auth_code():
    email = request.form.get("email", "")
    code = request.form.get("code", "")
    nxt = _safe_next(request.form.get("next", "/account"))
    user, err = accounts.verify_code(email, code)
    if err:
        body = f"""
  <div class="err">{_esc(err)}</div>
  <h1>That did not work</h1>
  <p><a class="btn" href="/login">Request a new code</a></p>
"""
        return _page("Sign in", body, robots="noindex")
    _establish(user)
    return redirect(nxt)


@bp.route("/auth/callback")
def auth_callback():
    """Landing page for the emailed link.

    Supabase returns the token after a '#', and browsers never send the part after
    a '#' to the server — so this page cannot read it in Python. The script below
    reads it in the browser and posts it back. If it is missing, that usually means
    the link was already used.
    """
    body = """
  <h1>Signing you in…</h1>
  <p id="msg" class="note">One moment.</p>
  <p id="fallback" style="display:none"><a class="btn" href="/login">Request a new link</a></p>
<script>
(function(){
  var h = window.location.hash || "";
  var p = new URLSearchParams(h.replace(/^#/, ""));
  var tok = p.get("access_token");
  var next = new URLSearchParams(window.location.search).get("next") || "";
  function fail(m){
    document.getElementById("msg").textContent = m;
    document.getElementById("fallback").style.display = "";
  }
  if (!tok) { fail("That sign-in link has expired or was already used."); return; }
  fetch("/auth/session", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({access_token: tok, next: next})
  }).then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.ok) { window.location.replace(d.next || "/account"); }
      else { fail((d && d.error) || "Could not sign you in."); }
    })
    .catch(function(){ fail("Could not reach the server. Try again."); });
})();
</script>
"""
    return _page("Signing in", body, robots="noindex")


@bp.route("/auth/session", methods=["POST"])
def auth_session():
    data = request.get_json(silent=True) or {}
    user, err = accounts.verify_access_token(data.get("access_token", ""))
    if err:
        return jsonify({"ok": False, "error": err}), 400
    _establish(user)
    nxt = data.get("next") or session.pop("login_next", None) or "/account"
    return jsonify({"ok": True, "next": _safe_next(nxt)})


def _establish(user):
    """Log in, and claim any purchases made with this address before the account
    existed."""
    accounts.log_in(user)
    try:
        billing.link_purchases_to_user(_sb(), user["email"], user["id"])
    except Exception as e:
        print(f"[paywall] link_purchases_to_user failed: {e}", flush=True)
    print(f"[paywall] Signed in: {user['email']}", flush=True)


@bp.route("/logout")
def logout():
    accounts.log_out()
    for k in ("paid_sid", "paid_repo", "paid_email"):
        session.pop(k, None)
    return redirect("/")


# ── Monitoring: expression of interest ─────────────────────────────────────────
# Not a product yet. This page measures whether anyone wants weekly monitoring of their own app,
# and how they'd want it delivered, before any of it is built. Answers go to the
# `monitoring_interest` table (supabase_monitoring_interest.sql); if that table has not been
# created yet the email still lands in the existing `waitlist` table with source "monitoring".
_MON_CHOICES = {
    "apps": {"1": "1 app", "2-3": "2 to 3 apps", "4-10": "4 to 10 apps", "10+": "More than 10 apps"},
    "visibility": {"public": "Public repositories", "private": "Private repositories", "both": "Both"},
    "delivery": {
        "watch": "Just watch my public repository, nothing to set up",
        "app": "A GitHub App I install with one click",
        "action": "A GitHub Action that runs inside my own repository",
        "unsure": "Not sure yet",
    },
    "price": {
        "u5": "Under $5 a month", "5-10": "$5 to $10 a month", "10-15": "$10 to $15 a month",
        "15-25": "$15 to $25 a month", "25+": "More than $25 a month", "unsure": "Not sure yet",
    },
}
_MON_HITS = {}
_MON_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


def _mon_rate_ok(ip, limit=5, window=3600):
    """At most `limit` submissions per connection per hour; in memory, per worker."""
    now = time.time()
    if len(_MON_HITS) > 5000:
        _MON_HITS.clear()
    hits = [x for x in _MON_HITS.get(ip, []) if now - x < window]
    ok = len(hits) < limit
    if ok:
        hits.append(now)
    _MON_HITS[ip] = hits
    return ok


def _mon_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "?")


def _store_monitoring_interest(row):
    """Returns 'new' (a first sign-up), 'updated' (same email again), 'fallback' (saved as an email-only
    waitlist entry because the interest table is missing) or 'none' (nothing stored)."""
    sb = _sb()
    if sb is None:
        print("[monitoring] no database configured; interest not stored", flush=True)
        return "none"
    try:
        sb.table("monitoring_interest").insert(row).execute()
        return "new"
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg:
            # Same email again: keep their latest answers rather than adding a second row.
            try:
                sb.table("monitoring_interest").update(
                    {k: v for k, v in row.items() if k != "email"}).eq("email", row["email"]).execute()
            except Exception:
                pass
            return "updated"
        print(f"[monitoring] interest table unavailable, saving the email to the waitlist instead: {e}", flush=True)
    try:
        sb.table("waitlist").insert({"email": row["email"], "analyses_count": 0, "source": "monitoring"}).execute()
        return "fallback"
    except Exception as e2:
        print(f"[monitoring] waitlist fallback failed (a duplicate is fine): {e2}", flush=True)
        return "none"


_MON_NOTIFY_HITS = []


def _mon_notify_ok(limit=20, window=3600):
    """Global cap on alert EMAILS per worker per hour, so a flood of sign-ups from many connections
    cannot flood Moses's inbox. The sign-ups themselves are still stored."""
    now = time.time()
    _MON_NOTIFY_HITS[:] = [x for x in _MON_NOTIFY_HITS if now - x < window]
    if len(_MON_NOTIFY_HITS) >= limit:
        return False
    _MON_NOTIFY_HITS.append(now)
    return True


def _notify_async(row):
    """Email Moses about a new sign-up without making the visitor wait on the mail server.
    Returns the thread (tests join it); None when the hourly cap is reached."""
    if not _mon_notify_ok():
        print("[monitoring] alert email cap reached this hour; sign-up stored, no email sent", flush=True)
        return None
    labels = {"apps": "How many apps", "visibility": "Public or private", "delivery": "How it should run", "price": "Fair price per month (AUD)"}
    answers = {labels[k]: _MON_CHOICES[k].get(row.get(k), "") for k in labels}
    t = threading.Thread(target=notify.send_monitoring_interest_alert,
                         args=(row["email"], row.get("repo", ""), answers, row.get("notes", "")), daemon=True)
    t.start()
    return t


def _mon_select(name, label):
    opts = '<option value="">Choose one</option>' + "".join(
        f'<option value="{k}">{_esc(v)}</option>' for k, v in _MON_CHOICES[name].items())
    return f'<label for="{name}">{_esc(label)}</label><select id="{name}" name="{name}">{opts}</select>'


@bp.route("/monitoring")
def monitoring_interest_page():
    thanks = request.args.get("thanks")
    err = request.args.get("err", "")[:160]
    banner = ""
    if thanks:
        banner = ('<div class="ok">Thank you, you are on the list. Monitoring is not available yet; '
                  'we will email you once, when it is, and only about that.</div>')
    if err:
        banner += f'<div class="err">{_esc(err)}</div>'
    src = request.args.get("src", "")
    src = src if src in _MON_SRC else ""
    body = f"""
  <div class="eyebrow">Coming, maybe</div>
  <h1>Monitoring: Verilay keeps watching your app</h1>
  <p>Register interest. Nothing is for sale yet and there is nothing to pay. This page exists to find out
  whether people want it, and how, before it is built.</p>
  {banner}
  <h2>What it would do</h2>
  <ul>
    <li>Re-check your app on a schedule and email you when something new turns up: a newly published
    security problem in a package you use, an exposed key, or a change in your grade.</li>
    <li>Tell you what changed since the last check, naming the specific issues, not just a number.</li>
    <li>We already do this for our own four apps, and show it on the homepage.</li>
  </ul>
  <p class="note">It would not be a penetration test or a guarantee. AI-written findings can vary between
  runs, so only named, recorded changes would be reported as fixed or new.</p>
  <div class="card" id="form">
    <form method="POST" action="/monitoring/interest" id="mon-form">
      <input type="hidden" name="src" value="{_esc(src)}">
      <label for="email">Your email</label>
      <input type="email" id="email" name="email" placeholder="you@example.com" autocomplete="email" required maxlength="254">
      <p class="note" style="margin:.35rem 0 1rem">Used only to tell you about monitoring. No spam.</p>
      <label for="repo">Your repository <span style="font-weight:400;color:#6b6966">(optional)</span></label>
      <input type="text" id="repo" name="repo" placeholder="github.com/you/your-app" autocomplete="off"
             autocapitalize="none" spellcheck="false" maxlength="120">
      <div style="height:.9rem"></div>
      {_mon_select("apps", "How many apps would you want watched?")}
      <div style="height:.9rem"></div>
      {_mon_select("visibility", "Are they public or private on GitHub?")}
      <p class="note" style="margin:.35rem 0 0">Tip: watching a <strong>private</strong> repository would need you to give Verilay
      lasting <strong>read-only</strong> access to the repositories you choose, through a GitHub App. Today&rsquo;s one-off
      private scan is different: Verilay removes its access straight after reading the code. You could remove that access
      at any time in your GitHub settings. Public repositories need nothing.</p>
      <div style="height:.9rem"></div>
      {_mon_select("delivery", "How would you want it to run?")}
      <div style="height:.9rem"></div>
      {_mon_select("price", "What would feel fair, per month (AUD)?")}
      <div style="height:.9rem"></div>
      <label for="notes">Anything else? <span style="font-weight:400;color:#6b6966">(optional)</span></label>
      <textarea id="notes" name="notes" rows="3" maxlength="300"></textarea>
      <div style="position:absolute;left:-9999px" aria-hidden="true">
        <label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label>
      </div>
      <p style="margin-top:1rem"><button class="btn" type="submit">Register interest</button></p>
    </form>
  </div>
  <p class="note">Questions? <a href="mailto:moses@verilay.dev">moses@verilay.dev</a>. See the
  <a href="/privacy">privacy policy</a>.</p>
"""
    script = ("<script>document.getElementById('mon-form').addEventListener('submit',function(){"
              "try{if(window.plausible)plausible('Monitoring Interest Submit',{props:{delivery:"
              "document.getElementById('delivery').value||'none',price:document.getElementById('price').value||'none'}})}"
              "catch(e){}});</script>")
    return _page("Monitoring", body + script)


# Which link brought someone to the monitoring form (26 Oct 2026, "what's next" line); kept at the start of their notes.
_MON_SRC = {"report": "the line at the end of a report", "compare": "the compare page", "footer": "the report footer"}


@bp.route("/monitoring/interest", methods=["POST"])
def monitoring_interest_submit():
    if request.form.get("website"):  # hidden field: only a bot fills it. Look like success, store nothing.
        return redirect("/monitoring?thanks=1#form")
    email = (request.form.get("email") or "").strip().lower()
    if len(email) > 254 or not _MON_EMAIL.match(email):
        return redirect("/monitoring?err=" + urllib.parse.quote("Please enter a valid email address.") + "#form")
    if not _mon_rate_ok(_mon_ip()):
        return redirect("/monitoring?err=" + urllib.parse.quote("Too many submissions from this connection. Please try again later.") + "#form")
    repo = re.sub(r"[^A-Za-z0-9_.\-/:@]", "", request.form.get("repo") or "")[:120]
    row = {"email": email, "repo": repo, "notes": (request.form.get("notes") or "").strip()[:300]}
    if request.form.get("src") in _MON_SRC:
        row["notes"] = (f"[from {_MON_SRC[request.form['src']]}] " + row["notes"]).strip()[:340]
    for key, choices in _MON_CHOICES.items():
        v = request.form.get(key, "")
        row[key] = v if v in choices else ""
    if _store_monitoring_interest(row) in ("new", "fallback"):
        _notify_async(row)
    return redirect("/monitoring?thanks=1#form")


# The early-access offer that pops up after a complete A-grade scan (app.js showMonitoringOffer). Same list as the
# /monitoring form: the plan is kept in the existing price answer, so no new table is needed. Prices are a test
# (A$3.99 Basic, A$9.99 Active, decided 25 Oct 2026); nothing is for sale and nothing is charged.
MONITORING_PLANS = {
    "basic": {"name": "Basic", "price": "A$3.99", "price_choice": "u5"},
    "active": {"name": "Active", "price": "A$9.99", "price_choice": "5-10"},
}


@bp.route("/monitoring/offer", methods=["POST"])
def monitoring_offer_submit():
    body = request.get_json(silent=True) or {}
    if body.get("website"):  # hidden field: only a bot fills it. Look like success, store nothing.
        return jsonify({"ok": True})
    email = str(body.get("email") or "").strip().lower()
    if len(email) > 254 or not _MON_EMAIL.match(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    plan = str(body.get("plan") or "")
    if plan not in MONITORING_PLANS:
        return jsonify({"error": "Choose Basic or Active."}), 400
    if not _mon_rate_ok(_mon_ip()):
        return jsonify({"error": "Too many sign-ups from this connection. Please try again later."}), 429
    method = "zip" if body.get("method") == "zip" else "github"
    repo = re.sub(r"[^A-Za-z0-9_.\-/:@]", "", str(body.get("repo") or ""))[:120]
    p = MONITORING_PLANS[plan]
    row = {"email": email, "repo": repo, "apps": "", "visibility": "",
           "delivery": "watch" if method == "github" else "unsure", "price": p["price_choice"],
           "notes": f"Early access from the A-grade pop-up: {p['name']} {p['price']}/month ({method} scan)"}
    if _store_monitoring_interest(row) in ("new", "fallback"):
        _notify_async(row)
    return jsonify({"ok": True})


@bp.route("/pro/early-access", methods=["POST"])
def pro_early_access_submit():
    """Early-access list for Verilay Pro (A$4.99 a scan, not on sale yet). The email joins the waitlist with source
    "pro-scan" and Moses gets an email. 5 per connection per hour; bot trap."""
    body = request.get_json(silent=True) or {}
    if body.get("website"):
        return jsonify({"ok": True})
    email = str(body.get("email") or "").strip().lower()
    if len(email) > 254 or not _MON_EMAIL.match(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    if not _mon_rate_ok("pro:" + _mon_ip()):
        return jsonify({"error": "Too many sign-ups from this connection. Please try again later."}), 429
    # product "fix": Verilay self fix (fix sessions, A$29), from its card on /pricing; same list, its own source.
    fix = body.get("product") == "fix"
    src = body.get("src") if body.get("src") in ("report", "compare", "footer") else ""     # which "what's next" link brought them
    sb = _sb()
    if sb is not None:
        try:
            sb.table("waitlist").insert({"email": email, "analyses_count": 0,
                                         "source": (("fix-session-" + src) if src else "fix-session") if fix else "pro-scan"}).execute()
        except Exception as e:
            print(f"[pro] waitlist insert skipped (a duplicate is fine): {e}", flush=True)
    if _mon_notify_ok():
        threading.Thread(target=notify.send_monitoring_interest_alert,
                         args=(email, "", {"Interested in": "Verilay Self Fix session, A$29 (early access)" if fix
                                           else "Verilay Pro scan, A$4.99 (early access)"},
                               "From the Verilay Self Fix session card on the Pricing page." if fix
                               else "From the locked fix prompts after a light free scan."), daemon=True).start()
    return jsonify({"ok": True})


# ── Private repositories: expression of interest ───────────────────────────────
# Verilay reads PUBLIC GitHub repositories only. This page measures whether people with private code want a way to
# connect it, and how, before anything is built. Answers go to the `private_repo_interest` table
# (supabase_private_repo_interest.sql); if that table has not been created yet the email still lands in the existing
# `waitlist` table with source "private-repos".
_PRIV_CHOICES = {
    "host": {"github": "GitHub", "gitlab": "GitLab", "bitbucket": "Bitbucket", "azure": "Azure DevOps", "other": "Somewhere else"},
    "connect": {
        "app": "A read-only GitHub App I install with one click, limited to the repositories I choose",
        "action": "A GitHub Action that runs inside my own repository",
        "local": "A command I run on my own computer, so my code never leaves it",
        "zip": "Uploading a ZIP each time is fine",
        "unsure": "Not sure yet",
    },
    "reason": {
        "customer": "It holds customer or personal data",
        "company": "It is my employer's or a client's code",
        "secrets": "It may contain keys or passwords I don't want exposed",
        "prefer": "I just prefer it private",
        "other": "Something else",
    },
    "repos": {"1": "1 repository", "2-3": "2 to 3 repositories", "4-10": "4 to 10 repositories", "10+": "More than 10 repositories"},
}
_PRIV_LABELS = {"host": "Where the code lives", "connect": "How they'd like to connect", "reason": "Why it is private",
                "repos": "How many private repositories"}


def _store_private_interest(row):
    """'new', 'updated' (same email again), 'fallback' (email-only waitlist entry because the table is missing) or 'none'."""
    sb = _sb()
    if sb is None:
        print("[private-repos] no database configured; interest not stored", flush=True)
        return "none"
    try:
        sb.table("private_repo_interest").insert(row).execute()
        return "new"
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg:
            try:
                sb.table("private_repo_interest").update(
                    {k: v for k, v in row.items() if k != "email"}).eq("email", row["email"]).execute()
            except Exception:
                pass
            return "updated"
        print(f"[private-repos] interest table unavailable, saving the email to the waitlist instead: {e}", flush=True)
    try:
        sb.table("waitlist").insert({"email": row["email"], "analyses_count": 0, "source": "private-repos"}).execute()
        return "fallback"
    except Exception as e2:
        print(f"[private-repos] waitlist fallback failed (a duplicate is fine): {e2}", flush=True)
        return "none"


def _priv_notify_async(row):
    """Email Moses about a new sign-up without making the visitor wait. Shares the hourly cap with the monitoring alerts.
    Returns the thread (tests join it); None when the cap is reached."""
    if not _mon_notify_ok():
        print("[private-repos] alert email cap reached this hour; sign-up stored, no email sent", flush=True)
        return None
    answers = {_PRIV_LABELS[k]: _PRIV_CHOICES[k].get(row.get(k), "") for k in _PRIV_LABELS}
    t = threading.Thread(target=notify.send_private_repo_interest_alert,
                         args=(row["email"], answers, row.get("notes", "")), daemon=True)
    t.start()
    return t


def _priv_select(name, label):
    opts = '<option value="">Choose one</option>' + "".join(
        f'<option value="{k}">{_esc(v)}</option>' for k, v in _PRIV_CHOICES[name].items())
    return f'<label for="{name}">{_esc(label)}</label><select id="{name}" name="{name}">{opts}</select>'


@bp.route("/private-repos")
def private_repo_interest_page():
    thanks = request.args.get("thanks")
    err = request.args.get("err", "")[:160]
    banner = ""
    if thanks:
        banner = ('<div class="ok">Thank you, you are on the list. Nothing is built yet; we will email you once, '
                  'when there is something to try, and only about that.</div>')
    if err:
        banner += f'<div class="err">{_esc(err)}</div>'
    body = f"""
  <div class="eyebrow">Interest list</div>
  <h1>Want Verilay to check a private repository?</h1>
  <p>Today, Verilay reads <strong>public</strong> GitHub repositories only, and it never reads private code from
  GitHub. If your code is private, this page is to tell us you would like a way to connect it. Nothing is for sale and
  nothing is built yet: this page exists to find out whether people want it, and how, before it is built.</p>
  {banner}
  <h2>What you can do today</h2>
  <ul>
    <li><strong>Upload a ZIP of your project</strong> on the <a href="/">homepage</a> for a free scan. Your code is read
    in memory and never saved.</li>
    <li>The deep scan needs a public GitHub repository, for now.</li>
  </ul>
  <h2>What it might look like</h2>
  <p>If it is built, the aim is read-only access, only to the repositories you choose, that you can remove at any
  time. Tell us which way would suit you. These are ideas, not promises.</p>
  <div class="card" id="form">
    <form method="POST" action="/private-repos/interest" id="priv-form">
      <label for="email">Your email</label>
      <input type="email" id="email" name="email" placeholder="you@example.com" autocomplete="email" required maxlength="254">
      <p class="note" style="margin:.35rem 0 1rem">Used only to tell you about private repository support. No spam.</p>
      {_priv_select("host", "Where does your code live?")}
      <div style="height:.9rem"></div>
      {_priv_select("connect", "How would you want to connect it?")}
      <div style="height:.9rem"></div>
      {_priv_select("reason", "What keeps it private?")}
      <div style="height:.9rem"></div>
      {_priv_select("repos", "How many private repositories?")}
      <div style="height:.9rem"></div>
      <label for="notes">Anything else? <span style="font-weight:400;color:#6b6966">(optional)</span></label>
      <textarea id="notes" name="notes" rows="3" maxlength="300"></textarea>
      <div style="position:absolute;left:-9999px" aria-hidden="true">
        <label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label>
      </div>
      <p style="margin-top:1rem"><button class="btn" type="submit">Register interest</button></p>
    </form>
  </div>
  <p class="note">Questions? <a href="mailto:moses@verilay.dev">moses@verilay.dev</a>. See the
  <a href="/privacy">privacy policy</a>.</p>
"""
    script = ("<script>document.getElementById('priv-form').addEventListener('submit',function(){"
              "try{if(window.plausible)plausible('Private Repo Interest Submit',{props:{connect:"
              "document.getElementById('connect').value||'none',host:document.getElementById('host').value||'none'}})}"
              "catch(e){}});</script>")
    return _page("Private repositories", body + script)


@bp.route("/private-repos/interest", methods=["POST"])
def private_repo_interest_submit():
    if request.form.get("website"):  # hidden field: only a bot fills it. Look like success, store nothing.
        return redirect("/private-repos?thanks=1#form")
    email = (request.form.get("email") or "").strip().lower()
    if len(email) > 254 or not _MON_EMAIL.match(email):
        return redirect("/private-repos?err=" + urllib.parse.quote("Please enter a valid email address.") + "#form")
    if not _mon_rate_ok("private:" + _mon_ip()):
        return redirect("/private-repos?err=" + urllib.parse.quote("Too many submissions from this connection. Please try again later.") + "#form")
    row = {"email": email, "notes": (request.form.get("notes") or "").strip()[:300]}
    for key, choices in _PRIV_CHOICES.items():
        v = request.form.get(key, "")
        row[key] = v if v in choices else ""
    if _store_private_interest(row) in ("new", "fallback"):
        _priv_notify_async(row)
    return redirect("/private-repos?thanks=1#form")


# ── Account ────────────────────────────────────────────────────────────────────
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


def _admin_sections():
    """The admin-only blocks, built once for the Admin page (/admin). Returns
    (admin_note, monitor_note, interest_note, private_note, clients_note); each is HTML.
    Moved here from /account on 21 Oct 2026 so the admin material is in one place and an ordinary
    signed-in user's account page never carries any of it. Only ever called for a signed-in admin."""
    admin_note = ""
    monitor_note = ""
    interest_note = ""
    private_note = ""
    clients_note = ""
    # Who has registered interest in monitoring (admin only: these are people's emails).
    try:
        _ir = _sb().table("monitoring_interest").select("*").order("created_at", desc=True).limit(50).execute().data or []
        _lab = lambda k, v: _esc(_MON_CHOICES.get(k, {}).get(v, v or "-"))
        _rows_i = "".join(
            f'<tr><td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_esc(str(r.get("created_at", ""))[:10])}</td>'
            f'<td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_esc(r.get("email"))}</td>'
            f'<td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_lab("apps", r.get("apps"))}<br>{_lab("visibility", r.get("visibility"))}</td>'
            f'<td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_lab("delivery", r.get("delivery"))}</td>'
            f'<td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_lab("price", r.get("price"))}</td>'
            f'<td style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0">{_esc(r.get("repo"))} {_esc(r.get("notes"))}</td></tr>'
            for r in _ir)
        interest_note = (
            f'<details class="acc"><summary>\U0001F4EC Monitoring interest ({len(_ir)})</summary><div class="acc-body">'
            + ('<div style="overflow-x:auto"><table style="width:100%;min-width:640px;border-collapse:collapse">'
               '<tr><th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">When</th>'
               '<th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">Email</th>'
               '<th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">Apps</th>'
               '<th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">Wants</th>'
               '<th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">Price</th>'
               '<th style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966">Repo / notes</th></tr>'
               + _rows_i + '</table></div>' if _ir else '<p class="note" style="margin:0">No one has registered yet.</p>')
            + '</div></details>')
    except Exception as _ie:
        interest_note = ('<details class="acc"><summary>\U0001F4EC Monitoring interest</summary><div class="acc-body">'
                         '<p class="note" style="margin:0">The interest table is not set up yet, so answers are '
                         'being saved as emails only (waitlist, source &ldquo;monitoring&rdquo;). Run '
                         'supabase_monitoring_interest.sql in Supabase to keep the full answers.</p></div></details>')
    # Who has registered interest in a way to connect a PRIVATE repository (admin only: these are people's emails).
    try:
        _pr = _sb().table("private_repo_interest").select("*").order("created_at", desc=True).limit(50).execute().data or []
        _plab = lambda k, v: _esc(_PRIV_CHOICES.get(k, {}).get(v, v or "-"))
        _cell = 'style="padding:6px 8px;font-size:12px;border-bottom:0.5px solid #e8e6e0"'
        _rows_p = "".join(
            f'<tr><td {_cell}>{_esc(str(r.get("created_at", ""))[:10])}</td>'
            f'<td {_cell}>{_esc(r.get("email"))}</td>'
            f'<td {_cell}>{_plab("host", r.get("host"))}<br>{_plab("repos", r.get("repos"))}</td>'
            f'<td {_cell}>{_plab("connect", r.get("connect"))}</td>'
            f'<td {_cell}>{_plab("reason", r.get("reason"))}</td>'
            f'<td {_cell}>{_esc(r.get("notes"))}</td></tr>'
            for r in _pr)
        _th = 'style="text-align:left;padding:6px 8px;font-size:11px;color:#6b6966"'
        private_note = (
            f'<details class="acc"><summary>\U0001F512 Private repo interest ({len(_pr)})</summary><div class="acc-body">'
            + ('<div style="overflow-x:auto"><table style="width:100%;min-width:640px;border-collapse:collapse">'
               f'<tr><th {_th}>When</th><th {_th}>Email</th><th {_th}>Where / how many</th><th {_th}>Wants</th>'
               f'<th {_th}>Why private</th><th {_th}>Notes</th></tr>'
               + _rows_p + '</table></div>' if _pr else '<p class="note" style="margin:0">No one has registered yet.</p>')
            + '</div></details>')
    except Exception:
        private_note = ('<details class="acc"><summary>\U0001F512 Private repo interest</summary><div class="acc-body">'
                        '<p class="note" style="margin:0">The interest table is not set up yet, so answers are '
                        'being saved as emails only (waitlist, source &ldquo;private-repos&rdquo;). Run '
                        'supabase_private_repo_interest.sql in Supabase to keep the full answers.</p></div></details>')
    # Who runs scans: browser / script / AI agent ... (a guess from the request's browser identity;
    # only the label is stored, see verilay_client_type.py).
    try:
        import verilay_client_type as _ct
        _rows_c = _sb().table("reports").select("created_at,client_type:data->>client_type") \
            .order("created_at", desc=True).limit(1000).execute().data or []
        _cnt = {}
        for _r in _rows_c:
            _k = _r.get("client_type") or "not recorded"
            _cnt[_k] = _cnt.get(_k, 0) + 1
        _order = list(_ct.LABELS) + ["not recorded"]
        _parts = "".join(
            f'<tr><td style="padding:4px 8px;font-size:13px">{_esc(_ct.LABELS.get(k, "Not recorded (older scans)"))}</td>'
            f'<td style="padding:4px 8px;font-size:13px;text-align:right">{_cnt[k]}</td></tr>'
            for k in _order if _cnt.get(k))
        clients_note = (
            f'<details class="acc"><summary>\U0001F916 Who runs scans (last {len(_rows_c)} reports)</summary><div class="acc-body">'
            + (f'<table style="border-collapse:collapse;min-width:260px">{_parts}</table>' if _parts else
               '<p class="note" style="margin:0">No scans recorded yet.</p>')
            + '<p class="note" style="margin:.6rem 0 0">A guess from the browser type each request announced. Nothing else is '
              'stored: no addresses and no browser strings. An AI agent that drives a real browser looks like a person, and '
              '&ldquo;not recorded&rdquo; means scans from before this was added.</p></div></details>')
    except Exception:
        clients_note = ('<details class="acc"><summary>\U0001F916 Who runs scans</summary><div class="acc-body">'
                        '<p class="note" style="margin:0">Not available right now.</p></div></details>')
    admin_note = (
        '<div class="card" style="background:#EEEDFE;border-color:#534AB7;margin-bottom:1rem">'
        '<p style="margin:0;font-size:13px;color:#3C3489">🔑 Admin access: you can deep-scan '
        '<strong>any</strong> repo directly from <a href="/deep-scan" style="color:#3C3489">'
        'Analyse</a> — no purchase needed, so it will not show in the "bought" list on your account page. '
        'Repos you have already scanned as admin get a Deep re-scan link (and a Quick scan link) under your reports on your account page.</p></div>'
    )

    # Real critical/warning counts, unlike the public homepage badge —
    # safe here because this whole block is already gated on is_admin,
    # i.e. only ever rendered for Moses's own signed-in account. Table
    # format (2026-09-15, Moses's request) rather than the stacked-card
    # layout used elsewhere on this page, specifically so this section
    # can be screenshotted/shown as evidence of results without any
    # extra reformatting on his end.
    import verilay_self_monitor as self_monitor
    import verilay_livewatch as livewatch
    mon_rows = self_monitor.admin_summary()
    if mon_rows:
        grade_color = {"A": "#1D9E75", "B": "#4A90D9", "C": "#EF9F27",
                       "D": "#E24B4A", "F": "#A32D2D"}
        # Hardcoded to match THIS page's own stylesheet (top of file) —
        # var(--mut)/var(--bdr)/var(--txt) are homepage-only CSS custom
        # properties that don't exist here, so they were silently no-ops
        # (found 2026-09-15 while reworking this section for mobile).
        th = ('padding:6px 10px;font-size:11px;font-weight:600;color:#6b6966;'
              'text-transform:uppercase;letter-spacing:.03em;text-align:left;'
              'border-bottom:1px solid #e8e6e0')
        td = 'padding:8px 10px;font-size:13px;vertical-align:top;border-bottom:0.5px solid #e8e6e0'

        def _cell(r):
            score = r.get("score") or "—"
            color = grade_color.get(score, "#1a1917")
            checked_abs = self_monitor._format_checked_at(r.get("last_checked_at"))
            checked_rel = self_monitor._humanize_ago_full(r.get("last_checked_at"))
            checked = (f'{checked_abs}<br><span class="note">{checked_rel}</span>'
                       if checked_abs else '<span class="note">never</span>')
            status = (f'<span style="color:#A32D2D">⚠ {_esc(str(r.get("last_error"))[:100])}</span>'
                      if r.get("last_error") else '<span style="color:#1D9E75">✓ OK</span>')
            # Straight to the DEEP scan gate, not the free homepage — as
            # admin this is the full-detail, fix-prompt-generating path,
            # not just a teaser. Opens in a new tab so the account page
            # stays put. This is a landing page with its own "Start the
            # deep scan" button (deep_scan() above), not an instant
            # trigger — and /start already redirects to any job already
            # running for this repo instead of duplicating it, so no
            # extra confirmation or dedup logic is needed here.
            repo = r.get("repo") or ""
            owner_name, _, name = repo.partition("/")
            scan_link = (
                f'<a href="/deep/{_esc(owner_name)}/{_esc(name)}" target="_blank" '
                f'rel="noopener" style="font-size:12px;font-weight:600">Deep scan &rarr;</a>'
                if owner_name and name else ""
            )
            # Free standard analysis of the same repo, for when a check
            # shows problems and Moses wants to read more about them.
            # Opens the homepage with the address filled in; he presses
            # Analyse (same /?scan= pre-fill the Your reports rows use).
            if _REPO_RE.match(repo):
                scan_link += (
                    f'<br><a href="/?scan={_esc(repo)}" target="_blank" rel="noopener" '
                    f'title="Run a fresh standard analysis of this app" '
                    f'style="font-size:12px;font-weight:600">Quick scan &rarr;</a>'
                )
            return (
                f'<tr>'
                f'<td style="{td}"><strong>{_esc(r.get("app_name") or "—")}</strong></td>'
                f'<td style="{td}">{_esc(r.get("repo") or "—")}</td>'
                f'<td style="{td};font-weight:700;color:{color}">{_esc(score)}</td>'
                f'<td style="{td};text-align:center">{r.get("critical") if r.get("critical") is not None else "—"}</td>'
                f'<td style="{td};text-align:center">{r.get("warnings") if r.get("warnings") is not None else "—"}</td>'
                f'<td style="{td}">{checked}</td>'
                f'<td style="{td}">{status}</td>'
                f'<td style="{td}">{livewatch.summary_html(r)}</td>'
                f'<td style="{td}">{scan_link}</td>'
                f'</tr>'
            )

        mon_table = (
            '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;'
            'min-width:760px">'
            '<tr>'
            f'<th style="{th}">App</th><th style="{th}">Repo</th><th style="{th}">Grade</th>'
            f'<th style="{th};text-align:center">Critical</th><th style="{th};text-align:center">Warnings</th>'
            f'<th style="{th}">Last checked</th><th style="{th}">Status</th><th style="{th}">Live site</th><th style="{th}"></th>'
            '</tr>'
            + "".join(_cell(r) for r in mon_rows)
            + '</table></div>'
        )
        try:
            mon_detail = self_monitor.admin_detail_html(mon_rows)
        except Exception as exc:  # detail is a bonus -- never break /account
            print(f"[account] monitor detail failed: {exc}", flush=True)
            mon_detail = ""
        monitor_note = (
            f'<details class="acc"><summary>📡 Monitored apps ({len(mon_rows)})</summary>'
            f'<div class="acc-body">{mon_table}{mon_detail}</div></details>'
        )
    return admin_note, monitor_note, interest_note, private_note, clients_note


_ADMIN_CSS = """<style>.wrap{max-width:1100px}
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin:.3rem 0 1.6rem}
.tool{display:block;background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:.85rem 1rem;text-decoration:none;color:#1a1917}
.tool b{display:block;font-size:14px;margin-bottom:.2rem;color:#3C3489}
.tool span{font-size:12.5px;color:#6b6966;line-height:1.45}
.tool:hover{border-color:#534AB7}
.grp{font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin:1.4rem 0 .5rem}
</style>"""

# (group, [(name, address, one-line explanation)]). To add an admin tool, add one line here.
_ADMIN_TOOLS = [
    ("Is everything working?", [
        ("Platform check", "/platform-health", "Tests the database, the AI model, GitHub, sign-in and payments for real, and says what to fix. Also counts down to the AI model's retirement."),
        ("Payments set-up", "/billing-health", "Is the deep-scan payment path wired up? Yes or no for each piece, no secrets."),
        ("Monitored-apps checker", "/self-monitor-health", "Is the checker that watches your own apps running, and when did it last succeed?"),
        ("Private-repo beta status", "/github/status", "Is the private-repo beta open, in admin-only mode, or off?"),
    ]),
    ("Cost and use", [
        ("Latest scans", "/admin/scans", "The newest scans in plain words: which app, GitHub/ZIP/live address/private, Free/Pro/Deep, grade, areas checked, signed in or not, with a link to each report."),
        ("AI costs", "/admin/costs", "What the AI is costing, split into free scans, monitoring our own apps, deep scans and questions, with the cost of one scan of each."),
        ("Pro launch survey", "/admin/pro-survey", "The answers people gave to unlock their free Pro scan, with totals, and how many free Pro scans are left."),
        ("Raw AI numbers", "/usage-summary", "The same counts as plain data, per day (technical)."),
        ("Scans so far", "/stats", "The running count of analyses."),
    ]),
    ("Review", [
        ("App directory review", "/apps/review", "Approve or hide apps people have listed in the directory."),
    ]),
]


def _admin_tools_html():
    out = []
    for group, tools in _ADMIN_TOOLS:
        cards = "".join(f'<a class="tool" href="{_esc(href)}" target="_blank" rel="noopener"><b>{_esc(name)}</b><span>{_esc(why)}</span></a>'
                        for name, href, why in tools)
        out.append(f'<div class="grp">{_esc(group)}</div><div class="tgrid">{cards}</div>')
    return "".join(out)


def _usd(x, places=2):
    return "&ndash;" if x is None else f"US${x:,.{places}f}"


def _costs_html(d):
    """The admin cost page body. Every number comes from verilay_usage.dashboard(); nothing here is guessed."""
    if not d.get("available"):
        return ('<div class="eyebrow">Admin</div><h1>AI costs</h1><div class="card"><p style="margin:0">The usage numbers are not available '
                f'right now ({_esc(d.get("reason", "unknown"))}).</p></div>')
    th = 'style="text-align:left;padding:7px 10px;font-size:11px;font-weight:600;color:#6b6966;text-transform:uppercase;letter-spacing:.03em;border-bottom:1px solid #e8e6e0"'
    thr = th.replace("text-align:left", "text-align:right")
    td = 'style="padding:8px 10px;font-size:13px;border-bottom:0.5px solid #e8e6e0"'
    tdr = td.replace('style="', 'style="text-align:right;white-space:nowrap;')
    warn = ""
    if not d.get("prices_set"):
        warn = ('<div class="card" style="background:#FEF9C3;border-color:#EF9F27;margin-bottom:1rem"><p style="margin:0;font-size:13px">'
                'Costs are blank because the AI prices are not set. Add AI_PRICE_INPUT_PER_MTOK and AI_PRICE_OUTPUT_PER_MTOK on Railway '
                '(US dollars per million tokens, from the price list of the model in use). Only counts are shown until then.</p></div>')

    def card(title, value, sub=""):
        return (f'<div class="tool" style="cursor:default"><b>{_esc(title)}</b><span style="font-size:20px;color:#1a1917;font-weight:700">{value}</span>'
                + (f'<br><span>{_esc(sub)}</span>' if sub else "") + '</div>')
    cards = (card(f"Last {d['days_with_data']} day(s) with data", _usd(d["total_usd"]), "AI only")
             + card("At this pace, per month", _usd(d["estimated_per_month_usd"]), "AI only; days without data are not counted")
             + card("Hosting per month", _usd(d["hosting_per_month_usd"]) if d["hosting_per_month_usd"] is not None else "not set",
                    "set HOSTING_COST_USD_PER_MONTH on Railway to include it")
             + card("All in, per month", _usd(d["all_in_per_month_usd"]) if d["all_in_per_month_usd"] is not None else "&ndash;", "AI plus hosting"))
    import verilay_usage as _u
    _spent, _budget = _u.today_cost_usd(), _u.budget_usd()
    if _spent is None:      # no prices (or no database): show no made-up money, only where the budget is set
        cards += card("Today so far (UTC)", "&ndash;", "needs the AI prices; the daily budget is VERILAY_DAILY_AI_BUDGET_USD on Railway")
    else:
        cards += card("Today so far (UTC)", _usd(_spent),
                      (f"of a {_usd(_budget)} daily budget: free scans pause when it is reached" if _budget else "no daily budget set")
                      + "; set VERILAY_DAILY_AI_BUDGET_USD on Railway to change it")
    rows = ""
    for c in d["categories"]:
        per = _usd(c["cost_per_unit_usd"]) if c["cost_per_unit_usd"] is not None else "&ndash;"
        rows += (f'<tr><td {td}><strong>{_esc(c["label"])}</strong></td><td {tdr}>{c["calls"]:,}</td>'
                 f'<td {tdr}>{(c["input_tokens"] + c["output_tokens"]):,}</td><td {tdr}>{_usd(c["cost_usd"])}</td>'
                 f'<td {tdr}>{c["units"]:,}</td><td {tdr}>{per}</td></tr>')
    table = ('<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:560px"><tr>'
             f'<th {th}>What it was for</th><th {thr}>AI calls</th><th {thr}>Tokens</th><th {thr}>Cost</th><th {thr}>Scans finished</th><th {thr}>Cost of one</th></tr>'
             + rows + '</table></div>')
    drows = ""
    for r in d["per_day"]:
        drows += (f'<tr><td {td}>{_esc(r["date"])}</td><td {tdr}>{_usd(r["scan"])}</td><td {tdr}>{_usd(r["monitor"])}</td>'
                  f'<td {tdr}>{_usd(r["deep"])}</td><td {tdr}>{_usd(r["ask"])}</td><td {tdr}><strong>{_usd(r["total_usd"])}</strong></td></tr>')
    daily = ('<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:560px"><tr>'
             f'<th {th}>Day</th><th {thr}>Free scans</th><th {thr}>Monitoring</th><th {thr}>Deep scans</th><th {thr}>Questions</th><th {thr}>Total</th></tr>'
             + drows + '</table></div>') if drows else '<p class="note">No days recorded yet.</p>'
    skipped = d.get("own_app_checks_skipped", 0)
    saved = (f'<p class="note" style="margin-top:.8rem">Own-app checks skipped because the code had not changed: <strong>{skipped:,}</strong> '
             '(each one is an AI scan that was not paid for).</p>')
    return (_ADMIN_CSS + '<div class="eyebrow">Admin</div><h1>AI costs</h1>' + warn
            + f'<div class="tgrid">{cards}</div>'
            + '<div class="grp">By what it was used for</div>' + table + saved
            + '<div class="grp">By day</div>' + daily
            + f'<p class="note" style="margin-top:1.2rem">{_esc(d.get("note", ""))} Estimates use the prices you set; they are not Anthropic\'s invoice. '
              'Compare with the Anthropic Console now and then.</p>'
            + '<p class="note"><a href="/admin">Back to Admin</a></p>')


@bp.route("/admin/costs")
def admin_costs():
    """What the AI is costing, split by purpose. Admin only; anyone else gets 'Not found'."""
    if not _is_admin_user(accounts.current_user()):
        return "Not found", 404
    import verilay_usage as _usage
    return _page("AI costs", _costs_html(_usage.dashboard(30)), robots="noindex")


@bp.route("/admin")
def admin_home():
    """One place for everything only the site's owner uses. Anyone else, signed in or not, gets 'Not found'."""
    user = accounts.current_user()
    if not _is_admin_user(user):
        return "Not found", 404
    admin_note, monitor_note, interest_note, private_note, clients_note = _admin_sections()
    people = f'<div class="grp">People and demand</div>{interest_note}{private_note}{clients_note}'
    body = (_ADMIN_CSS + '<div class="eyebrow">Admin</div><h1>Admin</h1>'
            + admin_note + _admin_tools_html() + people
            + (f'<div class="grp">Your own apps</div>{monitor_note}' if monitor_note else "")
            + '<p class="note" style="margin-top:2rem"><a href="/account">Back to your account</a></p>')
    return _page("Admin", body, robots="noindex")


@bp.route("/account")
@accounts.login_required
def account():
    user = accounts.current_user()
    rows = billing.purchases_for_email(_sb(), user["email"])
    reports = _reports_for_user(user)

    if rows:
        items = []
        for r in rows:
            active = r.get("_active")
            tag = ('<span class="tag">Active</span>' if active
                   else '<span class="tag tag-off">Ended</span>')
            repo = _esc(r.get("repo", ""))
            when = _esc(str(r.get("expires_at", ""))[:10])
            link = (f'<a href="/deep/{repo}" target="_blank" rel="noopener">Deep re-scan</a>' if active else "")
            items.append(
                f'<div class="row"><span><strong>{repo}</strong><br>'
                f'<span class="note">Re-scans included until {when}</span></span>'
                f'<span>{tag} &nbsp;{link}</span></div>'
            )
        purchases_html = '<div class="card">' + "".join(items) + "</div>"
    else:
        purchases_html = (
            '<div class="card"><p style="margin:0">Nothing bought with this address '
            'yet. If you paid with a different email, sign in with that one instead.</p></div>'
        )

    is_admin = user["email"].strip().lower() in billing.ADMIN_EMAILS

    deep_tag = ('<span class="tag" style="background:#EEEDFE;color:#3C3489">Deep scan</span>')

    def _report_rows(rs):
        items = []
        for rep in rs:
            repo = _esc(rep["repo"] or "")
            # Admin re-scan link on every report, not just purchased ones —
            # an admin's synthetic entitlement (see entitlement_for_request)
            # never writes a row to `purchases`, so the "Deep scans you have
            # bought" list above genuinely has nothing to show for a repo
            # scanned via the bypass. This is where an admin actually finds
            # their way back to re-scanning it.
            admin_rescan = (f' &nbsp;<a href="/deep/{repo}" target="_blank" rel="noopener">Deep re-scan</a>'
                             if is_admin and repo else "")
            # Fresh standard (free-analysis) scan of the same repo: opens the
            # homepage with the address filled in; the user presses Analyse.
            # Only for owner/name repos -- live-URL and ZIP reports have no
            # such address to pre-fill.
            quick_scan = (f' &nbsp;<a href="/?scan={repo}" target="_blank" rel="noopener" '
                          f'title="Run a fresh standard analysis of this repo">Quick scan</a>'
                          if _REPO_RE.match(rep["repo"] or "") else "")
            tag = f' {deep_tag}' if rep.get("is_deep") else ""
            items.append(
                f'<div class="row"><span><strong>{repo or "Untitled"}</strong>{tag}'
                f'<br><span class="note">{_esc(rep["when"])}</span></span>'
                f'<span>{_esc(rep["score"] or "—")} &nbsp;'
                f'<a href="/report/{_esc(rep["id"])}" target="_blank" rel="noopener">Open</a>{quick_scan}{admin_rescan}</span></div>'
            )
        return items

    def _group_html(rs, empty_msg):
        if not rs:
            return f'<div class="card"><p style="margin:0">{empty_msg}</p></div>'
        return '<div class="card">' + "".join(_report_rows(rs)) + "</div>"

    # Deep scans and free analyses are listed separately (2026-10-10, Moses's
    # request): an admin deep scan writes no row to `purchases`, so this list
    # was the only place a deep scan showed up -- indistinguishable from a
    # free analysis.
    deep_reports = [r for r in reports if r.get("is_deep")]
    private_reports = [r for r in reports if r.get("private") and not r.get("is_deep")]
    free_reports = [r for r in reports if not r.get("is_deep") and not r.get("private")]
    private_reports_html = _group_html(
        private_reports, 'No private reports yet. <a href="/github/connect">Scan a private repository</a> and its report shows up here, '
        'for you only, on any device.')
    deep_reports_html = _group_html(
        deep_reports, "No deep scan reports yet. When you run a deep scan, its report shows up here.")
    reports_html = _group_html(
        free_reports,
        "No free reports saved to this account yet. Any analysis you run while signed in shows up here."
        if reports else
        "No reports saved to this account yet. Any analysis you run while signed in shows up here.")

    admin_card = ""
    if is_admin:
        admin_card = (
            '<div class="card" style="background:#EEEDFE;border-color:#534AB7;margin-bottom:1rem">'
            '<p style="margin:0;font-size:13px;color:#3C3489">\U0001F511 You are signed in as the site admin. '
            '<a href="/admin" style="color:#3C3489;font-weight:600">Open the Admin page &rarr;</a> '
            'for the health checks, cost figures, reviews and who has asked for what. You can also deep-scan <strong>any</strong> repo '
            'from <a href="/deep-scan" style="color:#3C3489">Analyse</a> with no purchase, so it will not appear in the "bought" list below.</p></div>'
        )

    # A scan you started and then closed the tab on used to be genuinely lost
    # — nothing anywhere showed it was still going. This is the way back.
    active_jobs = deepscan.active_jobs_for_user(user["id"])
    running_note = ""
    if active_jobs:
        job_lines = "".join(
            f'<p style="margin:.35rem 0"><a href="/deep-job/{_esc(j["id"])}">{_esc(j.get("repo",""))}</a>'
            f' — {_esc(j.get("progress") or "Starting...")}</p>'
            for j in active_jobs
        )
        running_note = (
            '<div class="card" style="background:#EEF3FE;border-color:#4A78D9;margin-bottom:1rem">'
            '<p style="margin:0 0 .35rem;font-size:13px;font-weight:600;color:#1F3E7A">'
            '⏳ Deep scan in progress</p>'
            f'{job_lines}</div>'
        )

    # Three collapsible sections, collapsed by default (2026-09-15, Moses's
    # request) — reads as three plain buttons on a phone instead of a long
    # scroll of always-open cards. Native <details>, no JS: the user taps to
    # expand whichever one they actually came here for.
    #
    # Also widened from this shared shell's default 680px (built for narrow
    # login/checkout forms, which still want that width) to match the
    # homepage's 1100px -- Moses noticed /account only used the centre of the
    # page. Scoped to this page alone via an inline override rather than
    # changing _SHELL, since checkout/login/pricing share that stylesheet and
    # should stay narrow. max-width only affects desktop/tablet widths, so
    # this has no effect on the mobile layout above.
    body = f"""
  <style>.wrap{{max-width:1100px}}</style>
  <div class="eyebrow">Your account</div>
  <h1>{_esc(user["email"])}</h1>
  {running_note}
  {admin_card}
  <details class="acc"><summary>Deep scan reports ({len(deep_reports)})</summary>
    <div class="acc-body">{deep_reports_html}</div>
  </details>
  <details class="acc" id="private-reports"{" open" if private_reports else ""}><summary>Your private reports ({len(private_reports)})</summary>
    <div class="acc-body">{private_reports_html}</div>
  </details>
  <details class="acc" id="reports"><summary>Free reports ({len(free_reports)})</summary>
    <div class="acc-body">{reports_html}</div>
  </details>
  <details class="acc"><summary>Deep scans purchased ({len(rows)})</summary>
    <div class="acc-body">{purchases_html}</div>
  </details>
  <p class="note" style="margin-top:2rem">
    <a href="/" target="_blank" rel="noopener">Run an analysis</a> &nbsp;·&nbsp;
    <a href="/logout">Sign out</a> &nbsp;·&nbsp;
    Need help? <a href="mailto:moses@verilay.dev">moses@verilay.dev</a>
  </p>
  <!-- "Sign out" deliberately stays a normal navigation, not a new tab
       (2026-09-15) -- opening it in a new tab would leave THIS tab still
       showing "signed in" content while the session is actually gone
       elsewhere, which is more confusing than helpful. Every other link on
       this page opens in a new tab so a signed-in user can look at a report
       or kick off a scan without losing their place on /account. -->

  <!-- No script here on purpose (2026-10-10, Moses's request): the sections
       all start collapsed so the user picks what to open. A previous script
       force-opened the reports section for /account#reports, which is what the
       header "Your account" link used to point at; that link is now plain
       /account, so nothing opens by itself. -->
"""
    return _page("Your account", body, robots="noindex")


def _reports_for_user(user):
    """Reports linked to this account. Empty list if the column is not there yet."""
    sb = _sb()
    if sb is None:
        return []
    # `is_deep` pulls just the one flag out of the stored report JSON so the
    # list can tell deep scans from free analyses without loading every report.
    # If that JSON-path select is ever rejected, fall back to the plain list
    # (everything then shows as free) rather than losing the page.
    def _fetch(cols):
        return (sb.table("reports")
                  .select(cols)
                  .eq("user_id", user["id"])
                  .order("created_at", desc=True)
                  .limit(100)
                  .execute())
    try:
        try:
            res = _fetch("id,repo,score,created_at,is_deep:data->>is_deep_scan,private:data->>private")
        except Exception as e:
            print(f"[paywall] Deep-scan flag unavailable, listing without it: {e}", flush=True)
            res = _fetch("id,repo,score,created_at")
    except Exception as e:
        print(f"[paywall] Report list unavailable (has the migration run?): {e}", flush=True)
        return []
    out = []
    for r in (res.data or []):
        out.append({
            "id": r.get("id", ""),
            "repo": r.get("repo", ""),
            "score": r.get("score", ""),
            "when": str(r.get("created_at", ""))[:16].replace("T", " "),
            "is_deep": str(r.get("is_deep")).strip().lower() == "true",
            "private": str(r.get("private")).strip().lower() == "true",
        })
    return out


# ── The deep scan itself ───────────────────────────────────────────────────────
@bp.route("/deep/<owner>/<repo>")
def deep_scan(owner, repo):
    """Gate for the deep scan, and the start page once entitled.

    entitlement_for_request is the only thing standing between this page and
    a stranger's paid report — checked here and again in every route below
    that touches a job, never assumed to still hold from a page load ago.
    """
    full = billing.normalise_repo(f"{owner}/{repo}")
    if not full:
        return _page("Not found", "<h1>Not found</h1><p>That does not look like a "
                     "repository.</p>", robots="noindex"), 404

    ent = entitlement_for_request(full)
    if not ent:
        body = f"""
  <h1>No deep scan on {_esc(full)}</h1>
  <p>This page is for an app you have bought a deep scan for. Either that purchase
  has run out, or it was bought with a different email address.</p>
  <p><a class="btn" href="/login">Sign in</a>
     &nbsp;<a class="btn btn-quiet" href="/deep-scan">Buy a deep scan</a></p>
  <p class="note">The free analysis of any public repo is always available on the
  <a href="/">homepage</a>.</p>
"""
        return _page("Deep scan", body, robots="noindex"), 403

    body = f"""
  <div class="eyebrow">Deep scan</div>
  <h1>{_esc(full)}</h1>
  <p>Your purchase is active and includes re-scans until
  <strong>{_esc(str(ent.get("expires_at", ""))[:10])}</strong>.</p>
  <div class="card">
    <p style="margin-bottom:1rem">Reads up to 150 of your files instead of the free
    scan's 25, checks every dependency against OSV.dev with full detail, and merges
    everything into one report. Runs for a few minutes — close this tab if you like,
    the scan keeps going and the report is saved to your account when it's done.</p>
    <form method="POST" action="/deep/{_esc(owner)}/{_esc(repo)}/start">
      <button class="btn" type="submit">Start the deep scan</button>
    </form>
  </div>
  <p class="note"><a href="/">Run the free analysis meanwhile</a></p>
"""
    return _page("Deep scan", body, robots="noindex")


@bp.route("/deep/<owner>/<repo>/start", methods=["POST"])
def deep_scan_start(owner, repo):
    full = billing.normalise_repo(f"{owner}/{repo}")
    ent = entitlement_for_request(full) if full else None
    if not ent:
        return redirect(f"/deep/{_esc(owner)}/{_esc(repo)}")

    # A scan already going for this exact repo? Send them back to that one
    # instead of starting a second — running two at once wastes GitHub/Claude
    # calls on what will likely come back saying the same thing.
    existing = deepscan.active_job_for_repo(full)
    if existing:
        return redirect(f"/deep-job/{existing['id']}?already_running=1")

    # A purchased scan only reads public repositories (the repo may have been made private since it was
    # bought). The admin is exempt. Checked before anything is started or counted.
    if not _is_admin_user(accounts.current_user()):
        _err = _public_repo_error(full)
        if _err:
            return _page("Deep scan", f'<h1>This repository cannot be scanned</h1><p>{_esc(_err)}</p>'
                         '<p><a class="btn btn-quiet" href="/account">Back to your account</a></p>', robots="noindex"), 403

    # Captured HERE, in the real request with a real session — the scan
    # itself runs in a background thread with no session of its own, so
    # this is the only point the signed-in user can actually be read.
    user = accounts.current_user()
    user_id = user["id"] if user else None

    # The admin-bypass entitlement's id ("admin-bypass-<repo>") is not a real
    # purchases.id UUID — passing it through would fail deepscan_jobs' typed
    # purchase_id column and silently drop the job into this-process-only
    # memory. consume_scan() already no-ops on a falsy purchase_id, so None
    # is the correct value here, not a placeholder.
    purchase_id = None if str(ent["id"]).startswith("admin-bypass-") else ent["id"]

    # Too many deep scans running already? Say so kindly. Nothing has been created or used yet, so the buyer's
    # scan is untouched. The admin is exempt. (verilay_capacity.py)
    if not _is_admin_user(accounts.current_user()):
        from verilay_capacity import DEEP_SCAN_LIMIT, DEEP_BUSY_MESSAGE
        if deepscan.running_job_count() >= DEEP_SCAN_LIMIT:
            return _page("Deep scan", f'<h1>Busy right now</h1><p>{_esc(DEEP_BUSY_MESSAGE)}</p>'
                         f'<p><a class="btn" href="/deep/{_esc(owner)}/{_esc(repo)}">Try again</a></p>', robots="noindex"), 503

    job_id = deepscan.create_job(full, purchase_id, user_id)
    deepscan.start_job(job_id, user_id)
    return redirect(f"/deep-job/{job_id}")


@bp.route("/deep-job/<job_id>")
def deep_job_progress(job_id):
    """Polling page — Decision 1. The buyer can close this tab; the job keeps
    running server-side and the report is in their account either way."""
    job = deepscan.get_job(job_id)
    if not job:
        return _page("Not found", "<h1>Not found</h1><p>That job does not exist, "
                     "or this server has restarted since it ran.</p>",
                     robots="noindex"), 404

    ent = entitlement_for_request(job["repo"])
    if not ent:
        return _page("Deep scan", "<h1>Not your scan</h1><p>Sign in with the "
                     "email you purchased with to see this.</p>", robots="noindex"), 403

    if job["status"] == "done" and job.get("report_id"):
        return redirect(f"/report/{job['report_id']}")

    if job["status"] == "cancelled":
        body = f"""
  <div class="eyebrow">Deep scan cancelled</div>
  <h1>{_esc(job["repo"])}</h1>
  <div class="card">
    <p style="margin:0">You cancelled this scan. No report was saved and nothing was counted
    against your scans.</p>
  </div>
  <p class="note"><a href="/deep/{_esc(job["repo"])}">Start a new scan on this repo</a>
  &nbsp;·&nbsp; <a href="/account">Your account</a></p>
"""
        return _page("Deep scan cancelled", body, robots="noindex")

    if job["status"] == "interrupted":
        body = f"""
  <div class="eyebrow">Deep scan interrupted</div>
  <h1>{_esc(job["repo"])}</h1>
  <div class="card">
    <p style="margin:0">{_esc(job.get("error") or deepscan.INTERRUPTED_MESSAGE)}</p>
  </div>
  <p style="margin-top:1rem"><a class="btn" href="/deep/{_esc(job["repo"])}">Start it again</a></p>
  <p class="note"><a href="/account">Your account</a></p>
"""
        return _page("Deep scan interrupted", body, robots="noindex")

    already_running_banner = ""
    if request.args.get("already_running"):
        already_running_banner = (
            '<div class="card" style="background:#FFF7E6;border-color:#F4B740;margin-bottom:1rem">'
            '<p style="margin:0;font-size:13px;color:#7A5200">A scan was already running for this '
            'repo, so this is that one. Best to let it finish before starting another — running two '
            'at once will not make it faster and just gives you two reports to compare instead of '
            'one solid one.</p></div>'
        )

    body = f"""
  <div class="eyebrow">Deep scan running</div>
  <h1>{_esc(job["repo"])}</h1>
  {already_running_banner}
  <div class="card">
    <p id="progress-text" style="margin-bottom:0">{_esc(job.get("progress","Starting..."))}</p>
  </div>
  <form method="POST" action="/deep-job/{job_id}/cancel" id="cancel-form" style="margin-top:.75rem">
    <button type="submit" class="btn btn-quiet" style="font-size:13px">Cancel scan</button>
  </form>
  <p class="note">This usually takes several minutes for a real codebase. Feel free
  to close this tab — <a href="/account">your account</a> will have the report when
  it's ready, and this page will jump there automatically if you leave it open.</p>
<script>
(function() {{
  var jobId = {job_id!r};
  function poll() {{
    fetch('/deep-job/' + jobId + '/status').then(function(r) {{ return r.json(); }}).then(function(d) {{
      if (d.status === 'done' && d.report_id) {{
        window.location.href = '/report/' + d.report_id;
        return;
      }}
      if (d.status === 'cancelled') {{
        document.getElementById('progress-text').textContent = 'Cancelling — this stops at the next checkpoint, may take a moment.';
        setTimeout(function() {{ window.location.reload(); }}, 4000);
        return;
      }}
      if (d.status === 'interrupted') {{
        window.location.reload();
        return;
      }}
      if (d.status === 'error') {{
        document.getElementById('progress-text').textContent =
          'Something went wrong: ' + (d.error || 'unknown error') +
          '. Email moses@verilay.dev and it will be sorted out.';
        var cf = document.getElementById('cancel-form');
        if (cf) cf.style.display = 'none';
        return;
      }}
      document.getElementById('progress-text').textContent = d.progress || 'Working...';
      setTimeout(poll, 4000);
    }}).catch(function() {{ setTimeout(poll, 8000); }});
  }}
  setTimeout(poll, 4000);
}})();
</script>
"""
    return _page("Deep scan running", body, robots="noindex")


@bp.route("/deep-job/<job_id>/cancel", methods=["POST"])
def deep_job_cancel(job_id):
    """Best-effort, cooperative cancel — see deepscan.cancel_job() for why
    this can't be instant. Same entitlement check as every other job route,
    so only the person who can see this job can stop it."""
    job = deepscan.get_job(job_id)
    if not job:
        return redirect(f"/deep-job/{job_id}")
    ent = entitlement_for_request(job["repo"])
    if not ent:
        return _page("Deep scan", "<h1>Not your scan</h1><p>Sign in with the "
                     "email you purchased with to see this.</p>", robots="noindex"), 403
    deepscan.cancel_job(job_id)
    return redirect(f"/deep-job/{job_id}")


@bp.route("/deep-job/<job_id>/status")
def deep_job_status(job_id):
    job = deepscan.get_job(job_id)
    if not job:
        return jsonify({"status": "error", "error": "not found"}), 404
    ent = entitlement_for_request(job["repo"])
    if not ent:
        return jsonify({"status": "error", "error": "not entitled"}), 403
    return jsonify({
        "status": job["status"],
        "progress": job.get("progress", ""),
        "report_id": job.get("report_id"),
        "error": job.get("error"),
    })


# ── Ops ────────────────────────────────────────────────────────────────────────
@bp.route("/billing-health")
def billing_health():
    """Is the paid path wired up? No secrets, just yes/no per piece.

    Worth having because every failure here is silent from the outside: a missing
    webhook secret looks exactly like a working site right up to the first sale.

    ADMIN ONLY since 23 Oct 2026 (404 for everyone else): it states whether the paywall is on, that Stripe is in live mode,
    which settings exist and the Stripe account id, none of which a visitor needs.
    """
    if not _is_admin_user(accounts.current_user()):
        return "Not found", 404
    resp = jsonify({
        "paywall_enabled": billing.PAYWALL_ENABLED,
        "stripe_sdk": billing._HAS_STRIPE,
        "stripe_key": bool(billing.STRIPE_SECRET_KEY),
        "stripe_mode": "live" if billing.is_live_key() else "test",
        "webhook_secret": bool(billing.STRIPE_WEBHOOK_SECRET),
        "price_id": bool(billing.STRIPE_PRICE_ID),
        "price": billing.price_label(),
        "tax_code": billing.DEEP_SCAN_TAX_CODE,
        # The key's own account. If a price or webhook was created somewhere else,
        # this is the value that shows why nothing works.
        "stripe_account_hint": billing.account_hint(),
        "auth_configured": accounts.configured(),
        "secret_key_set": bool(os.getenv("SECRET_KEY", "").strip()),
        # Distinguishes "SUPABASE_ANON_KEY is set" from "it silently fell back to
        # the service key", which auth_configured alone cannot tell you.
        "supabase_anon_key_set": bool(os.getenv("SUPABASE_ANON_KEY", "").strip()),
        "supabase_keys_distinct": (
            bool(os.getenv("SUPABASE_ANON_KEY", "").strip())
            and os.getenv("SUPABASE_ANON_KEY", "").strip() != os.getenv("SUPABASE_KEY", "").strip()
        ),
        "supabase": _sb() is not None,
        "base_url": billing.BASE_URL,
        "sellable": bool(billing.PAYWALL_ENABLED and billing.configured()
                         and accounts.configured() and _sb() is not None
                         and os.getenv("SECRET_KEY", "").strip()),
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp
