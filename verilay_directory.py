"""
verilay_directory.py — the Verilay app directory (/apps).

A free, searchable home for apps built with AI tools. The only way in is a free
Verilay scan: at the end of a scan of a public GitHub repository the maker can
choose to list their app. Apps whose scan found no critical issues and graded A
or B carry the "Checked by Verilay" confidence stamp, dated, and it fades after
STAMP_DAYS so an old clean scan cannot be shown for ever.

Rules this module keeps:
  - Listing needs the scan's manage token (the browser that ran the scan), so a
    stranger holding a report link cannot list it.
  - The repository, grade and date come from the stored report on the server,
    never from the form. A report re-saved by a browser through /save-report is
    marked `_client_saved` by app.py and can never earn a listing or a stamp.
  - Nothing appears on /apps until Moses approves it on /apps/review. Every
    change to a listing sends it back for review.
  - The stamp is a confidence stamp, not a security guarantee, and says so.

The table is created by supabase_app_directory.sql. Moses's own monitored apps are added by
supabase_app_directory_own_apps.sql, with code_public = false (some of their repositories are private).

© 2026 Moses Ekbote.
"""

import datetime as _dt
import re
import smtplib
import threading
import time
import urllib.parse
from email.mime.text import MIMEText

from flask import Blueprint, Response, jsonify, redirect, request

bp = Blueprint("directory", __name__)

# Filled in by init() so this module never imports app.py (that would be circular).
_deps = {
    "sb": None,
    "get_ip": lambda: "unknown",
    "report_auth_info": lambda _i: (None, None),
    "report_row": lambda _i: None,
    "can_write_report": lambda _i: False,
    "is_admin": lambda: False,
    "page": None,
}

STAMP_DAYS = 90
TABLE = "app_listings"

BUILT_WITH = ["Lovable", "Bolt", "Replit", "Base44", "v0", "Cursor", "Windsurf",
              "Claude Code", "GitHub Copilot", "Other AI tool"]
CATEGORIES = {
    "business": "Business & productivity",
    "money": "Money & finance",
    "home": "Home & property",
    "health": "Health & fitness",
    "education": "Education & careers",
    "marketing": "Marketing & sales",
    "community": "Community & social",
    "ai": "AI tools",
    "developer": "Developer tools",
    "other": "Something else",
}
PRICING = {"free": "Free", "freemium": "Free with paid plans", "paid": "Paid"}

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def init(app, sb=None, get_ip=None, report_auth_info=None, report_row=None,
         can_write_report=None, is_admin=None, page=None):
    """Wire the blueprint into the app. Call once, from app.py."""
    _deps["sb"] = sb
    for key, fn in (("get_ip", get_ip), ("report_auth_info", report_auth_info), ("report_row", report_row),
                    ("can_write_report", can_write_report), ("is_admin", is_admin), ("page", page)):
        if fn:
            _deps[key] = fn
    app.register_blueprint(bp)
    return bp


def _esc(s):
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _clean(s, limit):
    return _CTRL.sub(" ", str(s or "")).strip()[:limit]


# ── Who may list, and who earns the stamp ─────────────────────────────────────

def scan_verdict(data):
    """(listable, stamped, reason) for a stored scan report.

    listable: a finished free scan of a public GitHub repository, saved by the server.
    stamped:  listable, every part analysed, no critical issues, grade A or B."""
    if not isinstance(data, dict) or data.get("deleted"):
        return False, False, "That scan could not be found. Please run a new free scan."
    if data.get("input_method", "github") != "github" or not data.get("repo"):
        return False, False, "Only scans of a public GitHub repository can be listed for now."
    if data.get("_client_saved"):
        return False, False, "This report was re-saved from a browser, so it cannot be listed. Please run a new free scan."
    if not data.get("layers"):
        return False, False, "The scan did not finish. Please run it again, then list your app."
    health = data.get("health") or {}
    crit = health.get("critical")
    stamped = (isinstance(crit, int) and crit == 0 and str(health.get("score") or "") in ("A", "B")
               and not data.get("analysis_incomplete"))
    return True, stamped, ""


def _checked_at(report_id, data):
    """When the analysis behind this report was made, as an ISO string (or None)."""
    rf = data.get("reused_from") if isinstance(data, dict) else None
    if isinstance(rf, dict) and rf.get("created_at"):
        return str(rf["created_at"])
    try:
        row = _deps["report_row"](report_id)
    except Exception:
        row = None
    return str(row.get("created_at")) if row and row.get("created_at") else None


def _parse_time(value):
    try:
        t = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)
    except Exception:
        return None


def _date_text(value):
    t = _parse_time(value)
    return t.strftime("%d %b %Y").lstrip("0") if t else ""


def stamp_is_fresh(row, now=None):
    if not row.get("stamped"):
        return False
    t = _parse_time(row.get("checked_at"))
    if not t:
        return False
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return (now - t).days < STAMP_DAYS


# ── Form checks ───────────────────────────────────────────────────────────────

def _valid_url(url):
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return False
    host = (p.hostname or "")
    return (p.scheme in ("http", "https") and "." in host and not p.username and not p.password
            and len(url) <= 200 and " " not in url)


def validate_form(form):
    """(clean fields, error message). Error is "" when everything is fine."""
    f = {
        "app_name": _clean(form.get("app_name"), 60),
        "tagline": _clean(form.get("tagline"), 140),
        "app_url": _clean(form.get("app_url"), 200),
        "built_with": _clean(form.get("built_with"), 40),
        "category": _clean(form.get("category"), 20),
        "pricing": _clean(form.get("pricing"), 20),
        "contact": _clean(form.get("contact"), 254),
        "beta_testers": bool(form.get("beta_testers")),
        "custom_work": bool(form.get("custom_work")),
    }
    if f["app_url"] and not re.match(r"^https?://", f["app_url"], re.I):
        f["app_url"] = "https://" + f["app_url"]
    if len(f["app_name"]) < 2:
        return f, "Please give your app a name."
    if len(f["tagline"]) < 10:
        return f, "Please say in one line what your app does (at least 10 characters)."
    if not _valid_url(f["app_url"]):
        return f, "Please enter the web address where people can use your app."
    if f["built_with"] not in BUILT_WITH:
        return f, "Please choose the AI tool you built it with."
    if f["category"] not in CATEGORIES:
        return f, "Please choose a category."
    if f["pricing"] not in PRICING:
        f["pricing"] = ""
    c = f["contact"]
    if not (_EMAIL.match(c) or (re.match(r"^https?://", c, re.I) and _valid_url(c))):
        return f, "Please give an email address or a web link where people can reach you."
    if not form.get("confirm"):
        return f, "Please confirm you built this app with AI tools and are happy for it to be listed."
    return f, ""


# ── Limits ────────────────────────────────────────────────────────────────────
_HITS = {}
_NOTIFY_HITS = []


def _rate_ok(ip, limit=5, window=3600):
    now = time.time()
    if len(_HITS) > 5000:
        _HITS.clear()
    hits = [x for x in _HITS.get(ip, []) if now - x < window]
    ok = len(hits) < limit
    if ok:
        hits.append(now)
    _HITS[ip] = hits
    return ok


def _notify_ok(limit=20, window=3600):
    now = time.time()
    _NOTIFY_HITS[:] = [x for x in _NOTIFY_HITS if now - x < window]
    if len(_NOTIFY_HITS) >= limit:
        return False
    _NOTIFY_HITS.append(now)
    return True


def _send_review_alert(row):
    """Email Moses that a listing is waiting. Best-effort, never raises."""
    try:
        import verilay_notify as notify
        to = notify.MONITORING_INTEREST_NOTIFY_EMAIL
        if not notify.configured() or not to:
            print("[directory] email not configured; listing stored without an alert", flush=True)
            return False
        lines = [
            "A new app listing is waiting for your review.", "",
            f"App: {row.get('app_name')}",
            f"What it does: {row.get('tagline')}",
            f"Web address: {row.get('app_url')}",
            f"Repository: github.com/{row.get('repo')}",
            f"Built with: {row.get('built_with')} (the scan guessed: {row.get('detected_with') or 'not recorded'})",
            f"Confidence stamp: {'yes' if row.get('stamped') else 'no'}",
            "", "Approve or hide it: https://verilay.dev/apps/review", "", "— Verilay",
        ]
        msg = MIMEText("\n".join(_clean(x, 300) for x in lines))
        msg["Subject"] = _clean(f"New app listing: {row.get('app_name')}", 120)
        msg["From"] = notify.FROM_ADDRESS
        msg["To"] = to
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", notify.ZEPTOMAIL_TOKEN)
            server.sendmail(notify.FROM_ADDRESS, [to], msg.as_string())
        return True
    except Exception as e:
        print(f"[directory] review alert failed: {e}", flush=True)
        return False


# ── Storage ───────────────────────────────────────────────────────────────────

def save_listing(row):
    """Insert or update the listing for row['repo']. Returns 'new', 'updated' or 'none'."""
    sb = _deps["sb"]
    if sb is None:
        return "none"
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    try:
        existing = sb.table(TABLE).select("id").eq("repo", row["repo"]).limit(1).execute().data or []
        if existing:
            sb.table(TABLE).update(dict(row, status="pending", updated_at=now)).eq("id", existing[0]["id"]).execute()
            return "updated"
        sb.table(TABLE).insert(dict(row, status="pending", updated_at=now)).execute()
        return "new"
    except Exception as e:
        print(f"[directory] could not save listing for {row.get('repo')}: {e}", flush=True)
        return "none"


def approved_listings():
    sb = _deps["sb"]
    if sb is None:
        return []
    try:
        rows = sb.table(TABLE).select("*").eq("status", "approved").order("updated_at", desc=True) \
            .limit(500).execute().data or []
    except Exception as e:
        print(f"[directory] could not read listings: {e}", flush=True)
        return []
    # Freshly stamped apps first, then everything else; newest first within each group.
    return sorted(rows, key=lambda r: 0 if stamp_is_fresh(r) else 1)


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/apps/list", methods=["POST"])
def list_app():
    body = request.get_json(silent=True) or {}
    if body.get("website"):  # hidden field only a bot fills in: look like success, store nothing
        return jsonify({"ok": True, "stamped": False})
    report_id = _clean(body.get("report_id"), 40)
    if not report_id or not _deps["can_write_report"](report_id):
        return jsonify({"ok": False, "error": "Only the browser that ran this scan can list it. "
                                              "Please run a new free scan of your app."}), 403
    data, _owner = _deps["report_auth_info"](report_id)
    listable, stamped, reason = scan_verdict(data)
    if not listable:
        return jsonify({"ok": False, "error": reason}), 400
    fields, err = validate_form(body)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    if not _rate_ok(_deps["get_ip"]()):
        return jsonify({"ok": False, "error": "Too many listings from this connection. Please try again later."}), 429
    row = dict(fields,
               repo=str(data.get("repo"))[:200],
               report_id=report_id,
               detected_with=_clean(data.get("built_with"), 120),
               stamped=bool(stamped),
               checked_at=_checked_at(report_id, data))
    result = save_listing(row)
    if result == "none":
        return jsonify({"ok": False, "error": "Sorry, the directory could not save your listing just now. "
                                              "Please try again in a few minutes."}), 503
    if _notify_ok():
        threading.Thread(target=_send_review_alert, args=(row,), daemon=True).start()
    return jsonify({"ok": True, "stamped": bool(stamped), "updated": result == "updated"})


_STYLE = """<style>
.wrap{max-width:860px}
.dir-tools{display:flex;gap:8px;flex-wrap:wrap;margin:1.25rem 0 1rem}
.dir-tools input[type=search]{flex:1 1 240px;padding:10px 12px;font-size:15px;border:1px solid #e8e6e0;border-radius:8px;font-family:inherit}
.dir-tools select{width:auto;flex:0 1 auto}
.dir-check{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:500;margin:0;padding:0 4px;cursor:pointer}
.dir-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:.75rem}
.app-card{background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem;display:flex;flex-direction:column;gap:.5rem;min-width:0}
.app-name{font-weight:700;font-size:16px;color:#1a1917;overflow-wrap:anywhere}
.app-line{font-size:13px;color:#4a4846;line-height:1.55;overflow-wrap:anywhere}
.chips{display:flex;gap:5px;flex-wrap:wrap}
.chip{font-size:11px;padding:2px 9px;border-radius:20px;background:#f0efec;color:#4a4846}
.stamp{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:20px;background:#E1F5EE;color:#085041;align-self:flex-start}
.stamp-old{background:#f0efec;color:#6b6966;font-weight:500}
.app-links{display:flex;gap:12px;flex-wrap:wrap;font-size:13px;margin-top:auto;padding-top:.25rem}
.dir-empty{background:#fff;border:0.5px dashed #c9c7c2;border-radius:12px;padding:1.5rem;text-align:center;color:#6b6966;font-size:14px}
</style>"""


def _card(r):
    fresh = stamp_is_fresh(r)
    date = _date_text(r.get("checked_at"))
    if fresh:
        stamp = (f'<span class="stamp" title="No critical issues found in what Verilay checked on {_esc(date)}. '
                 f'A confidence stamp, not a guarantee of security.">&#x2713; Checked by Verilay &middot; {_esc(date)}</span>')
    elif r.get("stamped") and date:
        stamp = f'<span class="stamp stamp-old">Checked {_esc(date)} &middot; due for a fresh check</span>'
    else:
        stamp = ""
    chips = [r.get("built_with"), CATEGORIES.get(r.get("category"), ""), PRICING.get(r.get("pricing") or "", "")]
    if r.get("beta_testers"):
        chips.append("Looking for beta testers")
    if r.get("custom_work"):
        chips.append("Open to custom work")
    chips_html = "".join(f'<span class="chip">{_esc(c)}</span>' for c in chips if c)
    rel = "noopener" if fresh else "nofollow ugc noopener"
    contact = r.get("contact") or ""
    contact_href = ("mailto:" + contact) if _EMAIL.match(contact) else contact
    repo = r.get("repo") or ""
    search = " ".join(str(x or "") for x in (r.get("app_name"), r.get("tagline"), r.get("built_with"),
                                              CATEGORIES.get(r.get("category"), ""), repo)).lower()
    return (
        f'<div class="app-card" data-search="{_esc(search)}" data-built="{_esc(r.get("built_with"))}" '
        f'data-cat="{_esc(r.get("category"))}" data-checked="{"1" if fresh else "0"}">'
        f'<div class="app-name">{_esc(r.get("app_name"))}</div>'
        f'<div class="app-line">{_esc(r.get("tagline"))}</div>'
        f'{stamp}<div class="chips">{chips_html}</div>'
        f'<div class="app-links">'
        f'<a href="{_esc(r.get("app_url"))}" target="_blank" rel="{rel}">Open the app &#x2197;</a>'
        f'<a href="{_esc(contact_href)}" target="_blank" rel="nofollow noopener">Contact the builder</a>'
        + (f'<a href="https://github.com/{_esc(repo)}" target="_blank" rel="nofollow noopener" style="color:#6b6966">Code</a>'
           if repo and r.get("code_public") is not False else "")
        + '</div></div>'
    )


_FILTER_JS = """<script>
(function(){
  var q=document.getElementById('dir-q'),b=document.getElementById('dir-built'),c=document.getElementById('dir-cat'),
      k=document.getElementById('dir-checked'),none=document.getElementById('dir-none');
  if(!q)return;
  function run(){
    var words=q.value.toLowerCase().split(/\\s+/).filter(Boolean),shown=0;
    document.querySelectorAll('.app-card').forEach(function(el){
      var ok=words.every(function(w){return el.dataset.search.indexOf(w)>-1;})
        &&(!b.value||el.dataset.built===b.value)&&(!c.value||el.dataset.cat===c.value)
        &&(!k.checked||el.dataset.checked==='1');
      el.style.display=ok?'':'none'; if(ok)shown++;
    });
    if(none)none.style.display=shown?'none':'block';
  }
  [q,b,c,k].forEach(function(el){el.addEventListener('input',run);el.addEventListener('change',run);});
})();
</script>"""


def _page(title, body, robots="index,follow"):
    page = _deps["page"]
    if page:
        return page(title, body, robots)
    html = (f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{_esc(title)} - Verilay</title>'
            f'<meta name="robots" content="{robots}"></head><body style="font-family:sans-serif;'
            f'background:#f8f8f7;color:#1a1917"><div class="wrap" style="margin:0 auto;padding:2rem 1rem">'
            f'{body}</div></body></html>')
    return Response(html, mimetype="text/html")


@bp.route("/apps")
def apps_page():
    rows = approved_listings()
    built_opts = '<option value="">Any AI tool</option>' + "".join(
        f'<option value="{_esc(b)}">{_esc(b)}</option>' for b in BUILT_WITH)
    cat_opts = '<option value="">Any category</option>' + "".join(
        f'<option value="{_esc(k)}">{_esc(v)}</option>' for k, v in CATEGORIES.items())
    if rows:
        listing = (f'<div class="dir-grid">{"".join(_card(r) for r in rows)}</div>'
                   '<div class="dir-empty" id="dir-none" style="display:none;margin-top:.75rem">'
                   'No apps match that yet. Try fewer words, or clear a filter.</div>')
        tools = (f'<div class="dir-tools"><input type="search" id="dir-q" placeholder="What do you need? e.g. booking, quotes, tracker" '
                 f'aria-label="Search apps"><select id="dir-built" aria-label="Built with">{built_opts}</select>'
                 f'<select id="dir-cat" aria-label="Category">{cat_opts}</select>'
                 f'<label class="dir-check"><input type="checkbox" id="dir-checked"> Checked only</label></div>')
    else:
        listing = ('<div class="dir-empty">No apps are listed yet. Built something with AI? '
                   '<a href="/">Run a free scan</a> and be one of the first.</div>')
        tools = ""
    body = f"""{_STYLE}
  <div class="eyebrow">App directory</div>
  <h1>Apps built with AI tools</h1>
  <p>Real apps made by founders, small businesses and first-time builders using Lovable, Bolt, Replit and other
  AI tools. Find something that solves your problem, try it, or get in touch with the person who built it.</p>
  {tools}
  {listing}
  <div class="card" style="margin-top:1.5rem">
    <h2 style="margin-top:0">Built an app with AI? List it free</h2>
    <p style="margin-bottom:.75rem">Run a free Verilay scan of your app's public GitHub repository. When it finishes,
    choose &ldquo;List my app&rdquo;. If the scan finds no critical issues, your listing carries the
    <strong>Checked by Verilay</strong> stamp.</p>
    <a class="btn" href="/">Run a free scan</a>
  </div>
  <p class="note"><strong>What the stamp means:</strong> on the date shown, a Verilay scan of the app's code
  found no critical issues and graded it A or B. It is a confidence stamp for new builders, not a security
  guarantee or a penetration test, and it fades after {STAMP_DAYS} days unless the app is checked again.
  Listings are written by the people who built the apps and are reviewed before they appear.</p>
"""
    return _page("Apps built with AI tools", body + (_FILTER_JS if rows else ""))


# ── Moses's review page ───────────────────────────────────────────────────────

def _same_origin():
    """Admin buttons must be pressed on this site, not on another page that posts here."""
    src = request.headers.get("Origin") or request.headers.get("Referer") or ""
    try:
        return urllib.parse.urlsplit(src).netloc == request.host
    except Exception:
        return False


@bp.route("/apps/review")
def review_page():
    if not _deps["is_admin"]():
        return Response("Not found", status=404)
    sb = _deps["sb"]
    rows, problem = [], ""
    if sb is not None:
        try:
            rows = sb.table(TABLE).select("*").order("updated_at", desc=True).limit(200).execute().data or []
        except Exception as e:
            problem = ("Could not read the listings table. If you have not yet, run supabase_app_directory.sql "
                       f"in Supabase. ({e})")
    order = {"pending": 0, "approved": 1, "hidden": 2}
    rows.sort(key=lambda r: order.get(r.get("status"), 3))
    items = []
    for r in rows:
        status = r.get("status") or "pending"
        buttons = "".join(
            f'<button class="btn{" btn-quiet" if act != "approve" else ""}" name="action" value="{act}" '
            f'style="padding:7px 14px;font-size:13px">{label}</button>'
            for act, label in (("approve", "Approve"), ("hide", "Hide"), ("pending", "Back to pending"))
            if act != {"approved": "approve", "hidden": "hide", "pending": "pending"}.get(status))
        items.append(
            f'<div class="card"><div style="display:flex;justify-content:space-between;gap:.5rem;flex-wrap:wrap">'
            f'<strong>{_esc(r.get("app_name"))}</strong><span class="tag{" tag-off" if status != "approved" else ""}">'
            f'{_esc(status)}</span></div>'
            f'<p style="margin:.4rem 0">{_esc(r.get("tagline"))}</p>'
            f'<p class="note" style="margin:0">App: <a href="{_esc(r.get("app_url"))}" target="_blank" rel="noopener">'
            f'{_esc(r.get("app_url"))}</a><br>Code: <a href="https://github.com/{_esc(r.get("repo"))}" target="_blank" '
            f'rel="noopener">github.com/{_esc(r.get("repo"))}</a><br>Built with: {_esc(r.get("built_with"))} '
            f'(scan guessed: {_esc(r.get("detected_with") or "not recorded")})<br>'
            f'Category: {_esc(CATEGORIES.get(r.get("category"), r.get("category")))} &middot; '
            f'Contact: {_esc(r.get("contact"))}<br>Stamp: {"yes" if r.get("stamped") else "no"}'
            f' &middot; checked {_esc(_date_text(r.get("checked_at")) or "?")}'
            f' &middot; scan report <a href="/report/{_esc(r.get("report_id"))}" target="_blank" rel="noopener">'
            f'{_esc(r.get("report_id"))}</a></p>'
            f'<form method="POST" action="/apps/review/{_esc(r.get("id"))}" '
            f'style="display:flex;gap:6px;flex-wrap:wrap;margin-top:.75rem">{buttons}</form></div>')
    pending = sum(1 for r in rows if (r.get("status") or "pending") == "pending")
    body = (f'<div class="eyebrow">Admin</div><h1>App listings to review</h1>'
            f'<p>{pending} waiting. Check the app is real, built with AI tools, and that the web address matches '
            f'the code. Only approved apps appear on <a href="/apps">/apps</a>.</p>'
            + (f'<div class="err">{_esc(problem)}</div>' if problem else "")
            + ("".join(items) or '<p class="note">No listings yet.</p>'))
    return _page("Review app listings", body, robots="noindex,nofollow")


@bp.route("/apps/review/<listing_id>", methods=["POST"])
def review_action(listing_id):
    if not _deps["is_admin"]():
        return Response("Not found", status=404)
    if not _same_origin():
        return Response("Please use the buttons on the review page.", status=403)
    status = {"approve": "approved", "hide": "hidden", "pending": "pending"}.get(request.form.get("action", ""))
    sb = _deps["sb"]
    if status and sb is not None and re.match(r"^[0-9a-fA-F-]{8,40}$", listing_id or ""):
        try:
            sb.table(TABLE).update({"status": status}).eq("id", listing_id).execute()
        except Exception as e:
            print(f"[directory] review update failed: {e}", flush=True)
    return redirect("/apps/review")
