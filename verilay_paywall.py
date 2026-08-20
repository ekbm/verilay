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

from flask import (Blueprint, request, redirect, jsonify, session,
                   render_template_string, Response)

import verilay_billing as billing
import verilay_accounts as accounts
import verilay_deepscan as deepscan

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
    '<svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" '
    'style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/>'
    '<path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" '
    'stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" '
    'stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg>'
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
input[type=text],input[type=email]{width:100%;padding:10px 12px;font-size:15px;border:1px solid #e8e6e0;border-radius:8px;background:#fff;font-family:inherit}
input:focus{outline:none;border-color:#534AB7}
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
        right = (f'<a href="/account" style="color:#6b6966;text-decoration:none">{_esc(user["email"])}</a>'
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
      <td style="padding:8px 0;font-size:13px;color:#4a4846">Same prompts, grounded in the exact packages found</td>
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
  {_WHAT_YOU_GET}
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

    body = f"""
  {notice}
  <div class="eyebrow">One-off payment</div>
  <h1>The deep scan</h1>
  <div class="price">{_esc(price)}</div>
  <p class="note" style="margin-top:-.5rem">plus applicable tax, calculated at checkout for your location</p>
  <p style="margin-top:.35rem">A deep scan of your app, and re-scans whenever you
  like for 30 days.</p>
  {_WHAT_YOU_GET}
  <div class="card">
    <form method="POST" action="/checkout">
      <label for="repo">Which app?</label>
      <input type="text" id="repo" name="repo" placeholder="github.com/you/your-app"
             autocomplete="off" autocapitalize="none" spellcheck="false" required>
      <p class="note" style="margin:.5rem 0 1rem">
        A deep scan is tied to one repository, so we need its address. It must be
        a public GitHub repo. Re-scans of this same app are included.
      </p>
      <button class="btn" type="submit">Continue to payment</button>
    </form>
  </div>
  <p class="note">Payment is handled by Stripe on their own page — Verilay never
  sees your card. Already bought one?
  <a href="/login">Sign in</a>.</p>
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
    password — we email you a link and a code.</p>
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="/account">
      <input type="email" name="email" value="{_esc(email)}" required>
      <p class="note" style="margin:.5rem 0 1rem">We will send a sign-in link to
      this address.</p>
      <button class="btn" type="submit">Email me a sign-in link</button>
    </form>
  </div>
  <p class="note">A receipt has been emailed to you by Stripe.</p>
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
            notice = f'<div class="ok">{_esc(msg)}</div>'
        else:
            notice = f'<div class="err">{_esc(msg)}</div>'

    if sent_to:
        body = f"""
  {notice}
  <h1>Check your email</h1>
  <p>We sent a sign-in link to <strong>{_esc(sent_to)}</strong>. Click it and you
  are in. If the link is awkward to use — say you are checking email on your
  phone but want to sign in here — the same email has a six-digit code:</p>
  <div class="card">
    <form method="POST" action="/auth/code">
      <input type="hidden" name="email" value="{_esc(sent_to)}">
      <input type="hidden" name="next" value="{_esc(nxt)}">
      <label for="code">Six-digit code</label>
      <input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
             pattern="[0-9]*" maxlength="8" placeholder="123456" required>
      <p class="note" style="margin:.5rem 0 1rem">The code expires in about an hour.</p>
      <button class="btn" type="submit">Sign in</button>
    </form>
  </div>
  <p class="note">Nothing arrived? Check spam, then
  <a href="/login">request another</a>.</p>
"""
        return _page("Check your email", body, robots="noindex")

    body = f"""
  {notice}
  <h1>Sign in</h1>
  <p>Accounts are for people who have bought a deep scan — the free analysis needs
  no account and never will. There is no password: we email you a link.</p>
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
  var next = new URLSearchParams(window.location.search).get("next") || "/account";
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
    return jsonify({"ok": True, "next": _safe_next(data.get("next", "/account"))})


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


# ── Account ────────────────────────────────────────────────────────────────────
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
            link = (f'<a href="/deep/{repo}">Re-scan</a>' if active else "")
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

    if reports:
        items = []
        for rep in reports:
            repo = _esc(rep["repo"] or "")
            # Admin re-scan link on every report, not just purchased ones —
            # an admin's synthetic entitlement (see entitlement_for_request)
            # never writes a row to `purchases`, so the "Deep scans you have
            # bought" list above genuinely has nothing to show for a repo
            # scanned via the bypass. This is where an admin actually finds
            # their way back to re-scanning it.
            admin_rescan = f' &nbsp;<a href="/deep/{repo}">Re-scan</a>' if is_admin and repo else ""
            items.append(
                f'<div class="row"><span><strong>{repo or "Untitled"}</strong>'
                f'<br><span class="note">{_esc(rep["when"])}</span></span>'
                f'<span>{_esc(rep["score"] or "—")} &nbsp;'
                f'<a href="/report/{_esc(rep["id"])}">Open</a>{admin_rescan}</span></div>'
            )
        reports_html = '<div class="card">' + "".join(items) + "</div>"
    else:
        reports_html = ('<div class="card"><p style="margin:0">No reports saved to this '
                        'account yet. Any analysis you run while signed in shows up here.</p></div>')

    admin_note = ""
    if is_admin:
        admin_note = (
            '<div class="card" style="background:#EEEDFE;border-color:#534AB7;margin-bottom:1rem">'
            '<p style="margin:0;font-size:13px;color:#3C3489">🔑 Admin access: you can deep-scan '
            '<strong>any</strong> repo directly from <a href="/deep-scan" style="color:#3C3489">'
            'Analyse</a> — no purchase needed, so it will not show in the "bought" list below. '
            'Repos you have already scanned as admin get a Re-scan link under Your reports.</p></div>'
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

    body = f"""
  <div class="eyebrow">Your account</div>
  <h1>{_esc(user["email"])}</h1>
  {running_note}
  {admin_note}
  <h2 id="reports">Your reports</h2>
  {reports_html}
  <h2>Deep scans you have bought</h2>
  {purchases_html}
  <p class="note" style="margin-top:2rem">
    <a href="/">Run an analysis</a> &nbsp;·&nbsp;
    <a href="/logout">Sign out</a> &nbsp;·&nbsp;
    Need help? <a href="mailto:moses@verilay.dev">moses@verilay.dev</a>
  </p>
"""
    return _page("Your account", body, robots="noindex")


def _reports_for_user(user):
    """Reports linked to this account. Empty list if the column is not there yet."""
    sb = _sb()
    if sb is None:
        return []
    try:
        res = (sb.table("reports")
                 .select("id,repo,score,created_at")
                 .eq("user_id", user["id"])
                 .order("created_at", desc=True)
                 .limit(100)
                 .execute())
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
    """
    return jsonify({
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
