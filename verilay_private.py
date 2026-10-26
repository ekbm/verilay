"""verilay_private.py - the private-repository beta: connect, choose, scan once, remove access, keep the report private (2026-10-20).

The flow (all of it behind a switch that is OFF by default, VERILAY_PRIVATE_REPOS):
  /github/connect   -> GitHub: the visitor installs Verilay (read-only) on their account and picks repositories
  /github/callback  <- GitHub: state checked, the visitor's identity checked against the installation (verilay_ghapp.verify_installation)
  /github/choose    -> a list of the repositories they allowed; they pick ONE
  /github/pick      -> the pick is checked again and remembered for ONE scan
  /analyse-stream   (method "github_private") -> begin_scan() checks everything, uses up one scan of the daily allowance, mints a
                       one-hour key for that one repository; the code is read once; Verilay then REMOVES its own installation.
  /private-report/claim/<id> -> the browser that ran the scan is allowed to open the report (a signed cookie); nobody else can,
                       except the account that ran it and a signed-in admin.

Since 25 Oct 2026 (Moses) a private scan needs a Verilay account (an email sign-in link): /github/connect shows a short
sign-in box first, and after the link the visitor comes back to it. The report is saved to that account, so it opens on any
device from the account page, still for nobody else.

Rules (decided with Moses):
  * Free beta with clear limits: per GitHub account per day and per day overall. Counters hold only a keyed hash of the account id.
    If the counters cannot be read, scanning is refused (fail closed).
  * A private report is never in the scan-result cache, the app directory, monitoring or a deep scan, and its link works only in the
    browser that ran the scan. It expires sooner than a public report (verilay_report_expiry).
  * Nothing secret is logged or shown. Every value shown to a visitor is escaped.
"""
import functools
import secrets
import time
from datetime import datetime, timedelta
from html import escape
from urllib.parse import quote

from flask import Blueprint, jsonify, redirect, request, session, make_response

import verilay_ghapp as gh
import verilay_report_expiry as _expiry
from verilay_checklist import _CSS, _LOGO

bp = Blueprint("private_repos", __name__)

STATE_MAX_AGE = 15 * 60
CONNECTION_MAX_AGE = 30 * 60
PICK_MAX_AGE = 15 * 60
MAX_OWNED_REPORTS = 20

_deps = {"get_sb": lambda: None, "is_admin": lambda: False, "report_auth_info": lambda rid: (None, None), "can_write_report": lambda rid: False,
         "secret": lambda: "dev", "current_uid": lambda: None}


class PrivateRefused(Exception):
    def __init__(self, user_message):
        super().__init__(user_message)
        self.user_message = user_message


def init(app, get_sb, is_admin, report_auth_info, can_write_report, secret, current_uid=None):
    _deps.update(get_sb=get_sb, is_admin=is_admin, report_auth_info=report_auth_info, can_write_report=can_write_report, secret=secret)
    if current_uid is not None:
        _deps["current_uid"] = current_uid
    app.register_blueprint(bp)


def _signed_in():
    try:
        return bool(_deps["current_uid"]())
    except Exception:
        return False


def _signin_page():
    """Step 1 for a visitor who is not signed in: one short box. The link brings them back to /github/connect."""
    lim = gh.limits()
    body = (
        '<p style="font-size:15px">We email you a sign-in link. No password.</p>'
        '<ul style="margin:0 0 .75rem 1.2rem;font-size:14px;color:#4a4846;line-height:1.65">'
        '<li><strong>Your report stays private to your account.</strong> Open it on any device; nobody else can.</li>'
        '<li>Verilay reads your code once, then removes its own access. We keep the report, never your code.</li>'
        f'<li>Free beta: {lim["per_account_day"]} private scan{"" if lim["per_account_day"] == 1 else "s"} a day.</li></ul>'
        '<form method="post" action="/login" style="background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem 1.15rem" '
        'onsubmit="var b=this.querySelector(\'button[type=submit]\');if(b){b.disabled=true;b.textContent=\'Sending... this can take up to a minute\';}">'
        '<input type="hidden" name="next" value="/github/connect">'
        '<label for="email" style="display:block;font-size:14px;font-weight:600;margin-bottom:.35rem">Your email</label>'
        '<input type="email" id="email" name="email" required autocomplete="email" placeholder="you@example.com" '
        'style="width:100%;box-sizing:border-box;border:0.5px solid #d3d1c7;border-radius:8px;padding:10px 12px;font-size:15px;font-family:inherit">'
        '<label style="display:flex;gap:8px;font-size:13px;margin:.6rem 0 .9rem"><input type="checkbox" name="optin_features" value="yes">'
        'Occasional emails about new Verilay features (optional)</label>'
        '<button type="submit" class="cta-btn" style="border:0;cursor:pointer">Email me a sign-in link</button>'
        '<p style="font-size:12px;color:#6b6966;margin:.6rem 0 0">We use your email to sign you in and to keep your private reports. '
        'Nothing else unless you tick the box. <a href="/privacy">Privacy policy</a></p></form>'
        '<p style="font-size:13px;margin-top:1rem">Already signed in on another device? Open the link on this one, or '
        '<a href="/">scan a public repository or a ZIP</a> with no account.</p>')
    return _page("Sign in to scan a private repository", body)


# ── who may use it ──────────────────────────────────────────────────────────

def allowed_now():
    m = gh.mode()
    if m == "off" or not gh.configured():
        return False
    return True if m == "open" else bool(_deps["is_admin"]())


# ── the daily allowance ─────────────────────────────────────────────────────

def _today():
    return datetime.utcnow().strftime("%Y-%m-%d")


def _key(account_hash=None):
    return f"private:{_today()}:" + (f"acct:{account_hash}" if account_hash else "total")


def _read(sb, key):
    res = sb.table("stats").select("value").eq("key", key).execute()
    return int(res.data[0]["value"] or 0) if res.data else 0


def _bump(sb, key):
    res = sb.table("stats").select("value").eq("key", key).execute()
    if res.data:
        sb.table("stats").update({"value": int(res.data[0]["value"] or 0) + 1}).eq("key", key).execute()
    else:
        sb.table("stats").insert({"key": key, "value": 1}).execute()


def allowance(account_hash):
    """{'account_left', 'total_left'}. Raises PrivateRefused when the counters cannot be read: no counters, no scanning."""
    sb = _deps["get_sb"]()
    if sb is None:
        raise PrivateRefused("Private scanning is paused for a moment. Please try again later.")
    try:
        lim = gh.limits()
        return {"account_left": max(0, lim["per_account_day"] - _read(sb, _key(account_hash))),
                "total_left": max(0, lim["per_day"] - _read(sb, _key()))}
    except PrivateRefused:
        raise
    except Exception:
        raise PrivateRefused("Private scanning is paused for a moment. Please try again later.")


def _check_allowance(account_hash):
    a = allowance(account_hash)
    if a["account_left"] <= 0:
        raise PrivateRefused(f"You have reached today's limit for the beta ({gh.limits()['per_account_day']} private scans per GitHub account per day). "
                             "Please try again tomorrow.")
    if a["total_left"] <= 0:
        raise PrivateRefused("The beta has reached its limit for today. Please try again tomorrow.")


COUNTER_KEEP_DAYS = 2          # today's and yesterday's daily counters are kept; older ones are deleted
_last_purge = 0.0


def _purge_old(sb):
    """Delete daily counters older than yesterday. Best effort, at most every 10 minutes per worker; never raises."""
    global _last_purge
    if time.time() - _last_purge < 600:
        return
    _last_purge = time.time()
    cutoff = (datetime.utcnow() - timedelta(days=COUNTER_KEEP_DAYS - 1)).strftime("%Y-%m-%d")
    try:
        sb.table("stats").delete().like("key", "private:%").lt("key", f"private:{cutoff}").execute()
    except Exception as e:
        print(f"[private] counter cleanup skipped: {type(e).__name__}", flush=True)


def _consume(account_hash):
    sb = _deps["get_sb"]()
    try:
        _bump(sb, _key(account_hash))
        _bump(sb, _key())
    except Exception:
        raise PrivateRefused("Private scanning is paused for a moment. Please try again later.")
    _purge_old(sb)


# ── pages ───────────────────────────────────────────────────────────────────

def _page(title, body_html, status=200):
    html = (f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex, nofollow"><title>{escape(title)} | Verilay</title><style>{_CSS}</style></head><body>'
            f'<nav><a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917">{_LOGO} <span style="vertical-align:middle">Verilay</span></a>'
            f'<a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a></nav>'
            f'<div class="wrap"><h1 style="font-size:24px;font-weight:700;margin-bottom:.75rem">{escape(title)}</h1>{body_html}</div></body></html>')
    resp = make_response(html, status)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _message(title, text, status=200):
    return _page(title, f'<p>{escape(text)}</p><p><a href="/">Back to Verilay</a></p>', status)


def _shown(e):
    """What to show for an error: the plain message for everyone, plus (for a signed-in admin only) the short, secret-free reason."""
    note = ""
    try:
        if getattr(e, "detail", "") and _deps["is_admin"]():
            note = f" (for the admin: {e.detail})"
    except Exception:
        note = ""
    return e.user_message + note


def _safe(fn):
    """Any unexpected error becomes a plain page (and a one-line log naming the step and the kind of error, never a value),
    instead of a bare server error that Cloudflare would turn into a 'Bad gateway' page."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except Exception as e:
            print(f"[private] unexpected error in {fn.__name__}: {type(e).__name__}", flush=True)
            note = ""
            try:
                if _deps["is_admin"]():
                    note = f" (for the admin: unexpected {type(e).__name__} in {fn.__name__})"
            except Exception:
                pass
            return _message("Something went wrong", "Something went wrong on our side. Please try again in a minute." + note, 500)
    return wrapper


def _not_open():
    return _message("Private repositories", "Scanning private repositories is a beta that is not open to you yet. "
                    "You can still scan a public repository, or upload a ZIP of your project, which keeps your code private.", 403)


def _fresh(entry, max_age):
    return isinstance(entry, dict) and isinstance(entry.get("t"), (int, float)) and 0 <= time.time() - entry["t"] <= max_age


# ── routes ──────────────────────────────────────────────────────────────────

@bp.route("/github/status")
def status():
    resp = jsonify({"enabled": bool(allowed_now()), "mode": gh.mode() if allowed_now() else "off"})
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _intro_page(csrf, error="", status=200):
    """The page a visitor reads, and agrees to, BEFORE they are sent to GitHub. Every number comes from the real settings."""
    lim = gh.limits()
    days = _expiry.private_days()
    err = f'<p style="background:#FEF3C7;color:#92400E;border-radius:8px;padding:.6rem .85rem;font-size:13px">{escape(error)}</p>' if error else ""
    body = (
        f'{err}<p style="font-size:15px">Before you connect GitHub, here is exactly what happens, what Verilay keeps, and the limits. '
        'You stay in control the whole time.</p>'
        '<h2 style="font-size:16px;margin:1.25rem 0 .4rem">What happens</h2>'
        '<ol style="margin:0 0 .75rem 1.2rem;font-size:14px;color:#4a4846;line-height:1.65">'
        '<li>You continue to GitHub and sign in if needed. GitHub asks you to choose <strong>one</strong> repository to share, read-only.</li>'
        '<li>You come back to Verilay and confirm that repository.</li>'
        '<li>Verilay reads its code <strong>once</strong>, then <strong>removes its own access</strong> to your GitHub account straight away.</li>'
        '<li>Verilay analyses what it read and shows a report that only <strong>you</strong> can open: in this browser, or from your account on any device.</li></ol>'
        '<h2 style="font-size:16px;margin:1.25rem 0 .4rem">What Verilay can and can&rsquo;t do</h2>'
        '<ul style="margin:0 0 .75rem 1.2rem;font-size:14px;color:#4a4846;line-height:1.65">'
        '<li><strong>Read-only.</strong> Verilay can read the code of that one repository. It can&rsquo;t change, delete or add anything.</li>'
        '<li><strong>One repository, one time.</strong> It can&rsquo;t see your other repositories, and its access is removed as soon as the code has been read.</li>'
        '<li><strong>Your code goes to an AI service.</strong> To analyse it, parts of your code are sent to Claude, made by Anthropic. '
        'Under Anthropic&rsquo;s business terms, content sent this way is not used to train its models.</li></ul>'
        '<h2 style="font-size:16px;margin:1.25rem 0 .4rem">What Verilay keeps</h2>'
        '<ul style="margin:0 0 .75rem 1.2rem;font-size:14px;color:#4a4846;line-height:1.65">'
        f'<li>The <strong>report</strong> (findings, score, file names and a summary), private to your account and removed after {days} days. <strong>Never your code.</strong></li>'
        f'<li>A daily count tied to a <strong>scrambled</strong> version of your GitHub account number, for about {COUNTER_KEEP_DAYS} days, to apply the daily limit.</li></ul>'
        '<h2 style="font-size:16px;margin:1.25rem 0 .4rem">The limits</h2>'
        '<ul style="margin:0 0 .75rem 1.2rem;font-size:14px;color:#4a4846;line-height:1.65">'
        f'<li>This is a <strong>free beta</strong>: {lim["per_account_day"]} private scan{"" if lim["per_account_day"] == 1 else "s"} per GitHub account per day. It may change or stop at any time.</li>'
        '<li>It is a <strong>first check</strong>, not a penetration test, and not a guarantee that an app is secure. It can miss things and can be wrong.</li></ul>'
        '<h2 style="font-size:16px;margin:1.25rem 0 .4rem">Prefer not to connect?</h2>'
        '<p style="font-size:14px">You can <a href="/">upload a ZIP of your project instead</a>. Your code stays under your control until you upload it. '
        'If you do connect, you can also remove the Verilay app at any time in your GitHub settings.</p>'
        '<form method="post" action="/github/connect" style="margin-top:1.25rem;background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem 1.15rem">'
        f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
        '<label style="display:block;font-size:14px;margin-bottom:.6rem"><input type="checkbox" name="agree" value="yes" id="agree"> '
        'I have read this, and I agree to the <a href="/terms" target="_blank" rel="noopener">Terms of Use</a>, the '
        '<a href="/privacy" target="_blank" rel="noopener">Privacy Policy</a> and the <a href="/ai-disclaimer" target="_blank" rel="noopener">AI Disclaimer</a>.</label>'
        '<label style="display:block;font-size:14px;margin-bottom:.9rem"><input type="checkbox" name="allowed" value="yes" id="allowed"> '
        'I own this repository, or I am allowed to share its code for analysis.</label>'
        '<button type="submit" id="go" class="cta-btn" style="border:0;cursor:pointer">Continue to GitHub</button>'
        '</form>')
    return _page("Connect a private repository (beta)", body, status)


@bp.route("/github/connect", methods=["GET", "POST"])
@_safe
def connect():
    if not allowed_now():
        return _not_open()
    if not _signed_in():
        return _signin_page()
    if request.method == "GET":
        csrf = secrets.token_urlsafe(16)
        session["gh_csrf0"] = {"s": csrf, "t": time.time()}
        return _intro_page(csrf)
    saved = session.pop("gh_csrf0", None)
    given = request.form.get("csrf", "")
    if not _fresh(saved, STATE_MAX_AGE) or not secrets.compare_digest(str(saved.get("s", "")), given):
        return _message("Please start again", "That page has expired. Please open the private repository page again.", 400)
    if request.form.get("agree") != "yes" or request.form.get("allowed") != "yes":
        csrf = secrets.token_urlsafe(16)
        session["gh_csrf0"] = {"s": csrf, "t": time.time()}
        return _intro_page(csrf, "Please tick both boxes to continue. Nothing is sent to GitHub until you do.", 400)
    state = secrets.token_urlsafe(24)
    session["gh_state"] = {"s": state, "t": time.time()}
    try:
        return redirect(gh.install_url(state), 302)
    except gh.GhAppError as e:
        return _message("Private repositories", _shown(e), 500)


@bp.route("/github/callback")
@_safe
def callback():
    if not allowed_now():
        return _not_open()
    if not _signed_in():
        return _message("Please sign in", "Your sign-in ended before GitHub connected. Please sign in and connect again; nothing was read.", 400)
    if request.args.get("error"):
        return _message("Not connected", "GitHub did not connect Verilay, so nothing was read. You can try again whenever you like.")
    if request.args.get("setup_action") == "request":
        return _message("Waiting for approval", "Your organisation's owner has to approve Verilay on GitHub first. Once they have, connect again.")
    saved = session.pop("gh_state", None)
    given = request.args.get("state", "")
    if not _fresh(saved, STATE_MAX_AGE) or not isinstance(given, str) or not secrets.compare_digest(str(saved.get("s", "")), given):
        return _message("Please start again", "That connection link has expired or didn't start here. Please start again from Verilay.", 400)
    try:
        user_token = gh.exchange_code(request.args.get("code", ""))
        uid, installation_id = gh.verify_installation(user_token, request.args.get("installation_id", ""))
        user_token = None                                   # used once, now dropped
    except gh.GhAppError as e:
        if e.detail:
            print(f"[private] connect refused: {e.detail}", flush=True)
        return _message("Could not connect", _shown(e), 400)
    session["gh_priv"] = {"inst": installation_id, "uh": gh.account_hash(uid, _deps["secret"]()), "t": time.time()}
    return redirect("/github/choose", 302)


def _connection():
    c = session.get("gh_priv")
    return c if _fresh(c, CONNECTION_MAX_AGE) and isinstance(c.get("inst"), int) else None


@bp.route("/github/choose")
@_safe
def choose():
    if not allowed_now():
        return _not_open()
    c = _connection()
    if not c:
        return _message("Please start again", "Your connection has expired. Please connect your repository again.", 400)
    try:
        repos = gh.list_repos(gh.installation_token(c["inst"]))
        left = allowance(c["uh"])
    except gh.GhAppError as e:
        if e.detail:
            print(f"[private] choose failed: {e.detail}", flush=True)
        return _message("Could not read your repositories", _shown(e), 500)
    except PrivateRefused as e:
        return _message("Private repositories", _shown(e), 500)
    csrf = secrets.token_urlsafe(16)
    session["gh_csrf"] = csrf
    lim = gh.limits()
    intro = ('<p>Pick <strong>one</strong> repository to check. Verilay has <strong>read-only</strong> access: it reads the code once, '
             'then removes its own access to your GitHub account straight away. Nothing is changed in your repository.</p>'
             f'<p style="font-size:13px;color:#6b6966">This is a free beta with limits: {lim["per_account_day"]} private scans per GitHub account per day. '
             f'You have {escape(str(left["account_left"]))} left today.</p>')
    intro += (f'<p style="font-size:13px;color:#6b6966"><strong>What we keep:</strong> the report (findings, score and file names), private to your account '
              f'and removed after {_expiry.private_days()} days. Never your code. <a href="/privacy">Privacy policy</a></p>')
    if any(not r["private"] for r in repos):
        intro += ('<p style="font-size:13px;color:#6b6966">A repository marked <em>public</em> can also be scanned the normal way, '
                  'with just its link, so it does not need this private route.</p>')
    if not repos:
        return _page("Choose a repository", intro + '<p>No repositories were shared with Verilay. Connect again and select the one you want checked.</p>')
    rows = "".join(
        f'<form method="post" action="/github/pick" style="margin:0 0 .5rem"><input type="hidden" name="csrf" value="{escape(csrf)}">'
        f'<input type="hidden" name="repo" value="{escape(r["full_name"])}">'
        f'<button type="submit" style="width:100%;text-align:left;padding:.7rem 1rem;border:0.5px solid #e8e6e0;border-radius:10px;background:#fff;cursor:pointer;font-size:14px">'
        f'{escape(r["full_name"])} <span style="color:#6b6966;font-size:12px">{"private" if r["private"] else "public"}</span></button></form>' for r in repos)
    return _page("Choose a repository", intro + rows)


@bp.route("/github/pick", methods=["POST"])
@_safe
def pick():
    if not allowed_now():
        return _not_open()
    if not _signed_in():
        return _message("Please sign in", "Please sign in and connect your repository again.", 400)
    c = _connection()
    sent = request.form.get("csrf", "")
    want = session.pop("gh_csrf", "")
    if not c or not want or not secrets.compare_digest(str(want), str(sent)):
        return _message("Please start again", "That page has expired. Please connect your repository again.", 400)
    full = request.form.get("repo", "")
    parts = gh.valid_repo(full)
    if not parts:
        return _message("Choose a repository", "That repository name doesn't look right.", 400)
    try:
        repos = gh.list_repos(gh.installation_token(c["inst"]))
        if full not in {r["full_name"] for r in repos}:
            return _message("Choose a repository", "That repository isn't one you shared with Verilay.", 400)
        _check_allowance(c["uh"])
    except gh.GhAppError as e:
        return _message("Could not check that repository", _shown(e), 500)
    except PrivateRefused as e:
        return _message("Private repositories", e.user_message, 429)
    session["gh_pick"] = {"repo": full, "t": time.time()}
    return redirect("/?private_repo=" + quote(full, safe="/"), 302)


# ── the scan itself ─────────────────────────────────────────────────────────

def begin_scan(repo_full):
    """Everything that must be true before a private scan starts. Single use. Returns the scan details, or raises PrivateRefused."""
    if not allowed_now():
        raise PrivateRefused("Scanning private repositories isn't open to you yet.")
    if not _signed_in():
        raise PrivateRefused("Please sign in, then connect and choose the repository again.")
    parts = gh.valid_repo(repo_full)
    if not parts:
        raise PrivateRefused("That repository name doesn't look right.")
    conn, pick = session.pop("gh_priv", None), session.pop("gh_pick", None)       # single use: a refresh or second tab cannot repeat it
    if not _fresh(conn, CONNECTION_MAX_AGE) or not _fresh(pick, PICK_MAX_AGE) or pick.get("repo") != repo_full or not isinstance(conn.get("inst"), int):
        raise PrivateRefused("Please connect and choose the repository again.")
    inst = conn["inst"]
    try:
        _check_allowance(conn["uh"])
        token = gh.installation_token(inst, parts[1])
    except gh.GhAppError as e:
        gh.delete_installation(inst)
        raise PrivateRefused(_shown(e))
    except PrivateRefused:
        gh.delete_installation(inst)
        raise
    try:
        _consume(conn["uh"])
    except PrivateRefused:
        gh.delete_installation(inst)
        raise
    return {"token": token, "owner": parts[0], "repo": parts[1], "installation_id": inst, "uh": conn["uh"]}


def finish_access(scan):
    """The code has been read: drop the key and remove Verilay's installation. Never raises."""
    try:
        scan["token"] = None
        if scan.get("removed"):              # already done (the stream closing calls this again): one request is enough
            return True
        ok = gh.delete_installation(scan.get("installation_id"))
        scan["removed"] = bool(ok)
        print(f"[private] access removed: {'yes' if ok else 'NOT CONFIRMED'}", flush=True)
        return ok
    except Exception:
        return False


# ── keeping the report private ──────────────────────────────────────────────

def viewer_ok(report_id):
    """May this request open this private report? Only the browser that ran the scan, or a signed-in admin."""
    try:
        if _deps["is_admin"]():
            return True
        if str(report_id) in (session.get("pv_reports") or []):
            return True
        uid = _deps["current_uid"]()
        return bool(uid) and _deps["report_auth_info"](report_id)[1] == uid
    except Exception:
        return False


def gate(data, report_id):
    """Return the report if it may be shown to this request, else None (which every page treats as 'not found')."""
    if isinstance(data, dict) and data.get("private") and not viewer_ok(report_id):
        return None
    return data


@bp.route("/private-report/claim/<report_id>", methods=["POST"])
def claim(report_id):
    if not isinstance(report_id, str) or not (8 <= len(report_id) <= 40) or not report_id.isalnum():
        return jsonify({"ok": False}), 400
    data, _owner = _deps["report_auth_info"](report_id)
    if not isinstance(data, dict) or not data.get("private"):
        return jsonify({"ok": False}), 404
    if not _deps["can_write_report"](report_id):          # must present this report's own private key
        return jsonify({"ok": False}), 403
    owned = [r for r in (session.get("pv_reports") or []) if r != report_id] + [report_id]
    session["pv_reports"] = owned[-MAX_OWNED_REPORTS:]
    resp = jsonify({"ok": True})
    resp.headers["Cache-Control"] = "no-store"
    return resp
