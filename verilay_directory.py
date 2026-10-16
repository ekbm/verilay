"""
verilay_directory.py — the Verilay app directory (/apps).

A free, searchable home for apps built with AI tools. The only way in is a free
Verilay scan: at the end of a scan of a public GitHub repository the maker can
choose to list their app. Apps whose scan found no critical issues and graded A
or B carry the "Checked by Verilay" confidence stamp, dated, and it fades after
STAMP_DAYS so an old clean scan cannot be shown for ever.

Every approved app has its own page, /apps/<slug>, with its check status, a
"Contact the builder" form and the stamp makers can put on their own sites
(/apps/<slug>/stamp.svg, drawn live so it never claims more than is true now).

Rules this module keeps:
  - Listing needs the scan's manage token (the browser that ran the scan), so a
    stranger holding a report link cannot list it.
  - The repository, grade and date come from the stored report on the server,
    never from the form. A report re-saved by a browser through /save-report is
    marked `_client_saved` by app.py and can never earn a listing or a stamp.
  - Nothing appears on /apps until Moses approves it on /apps/review. Every
    change to a listing sends it back for review.
  - The builder's email is never shown. Visitors write through the contact form;
    Verilay emails the builder with the visitor as Reply-To, and keeps the
    visitor's email and message (shown to Moses only, on /apps/review).
  - The stamp is a confidence stamp, not a security guarantee, and says so.

Tables: supabase_app_directory.sql, then supabase_app_directory_v2.sql (builder
name, slug, contact messages). Moses's own monitored apps are added by
supabase_app_directory_own_apps.sql, with code_public = false (some of their
repositories are private).

© 2026 Moses Ekbote.
"""

import datetime as _dt
import re
import secrets
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
CONTACTS = "app_contacts"

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

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,58}[a-z0-9])?$")
# Words used by the directory's own pages; an app can never take them as its address.
_RESERVED = {"list", "review", "stamp", "contact", "admin", "new", "search", "apps"}


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


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", str(name or "").lower()).strip("-")[:40].strip("-") or "app"
    return s + "-app" if s in _RESERVED else s


def app_path(row):
    slug = (row or {}).get("slug") or ""
    return "/apps/" + slug if _SLUG.match(slug) else ""


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


def stamp_state(row, now=None):
    """'fresh', 'expired' or 'none'."""
    if not row or not row.get("stamped"):
        return "none"
    if stamp_is_fresh(row, now):
        return "fresh"
    return "expired" if _parse_time(row.get("checked_at")) else "none"


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
        "builder_name": _clean(form.get("builder_name"), 60),
        "contact": _clean(form.get("contact"), 254).lower(),
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
    if len(f["builder_name"]) < 2:
        return f, "Please add your name (or your business name). It is shown on your listing."
    if not _EMAIL.match(f["contact"]):
        return f, "Please give your email address. It stays private: visitors' messages are sent to it."
    if not form.get("confirm"):
        return f, "Please confirm you built this app with AI tools and are happy for it to be listed."
    return f, ""


# ── Limits ────────────────────────────────────────────────────────────────────
_HITS = {}
_CONTACT_HITS = {}
_NOTIFY_HITS = []
_MAIL_HITS = []


def _hit_ok(store, key, limit, window):
    now = time.time()
    if len(store) > 5000:
        store.clear()
    hits = [x for x in store.get(key, []) if now - x < window]
    ok = len(hits) < limit
    if ok:
        hits.append(now)
    store[key] = hits
    return ok


def _rate_ok(ip, limit=5, window=3600):
    return _hit_ok(_HITS, ip, limit, window)


def _cap_ok(store, limit, window=3600):
    now = time.time()
    store[:] = [x for x in store if now - x < window]
    if len(store) >= limit:
        return False
    store.append(now)
    return True


def _notify_ok(limit=20, window=3600):
    return _cap_ok(_NOTIFY_HITS, limit, window)


# ── Email ─────────────────────────────────────────────────────────────────────

# Emails to builders come from Moses himself: a person, not a no-reply robot. If the mail service
# refuses that sender (not yet allowed in ZeptoMail), the same email goes from noreply@ instead.
BUILDER_FROM = "moses@verilay.dev"
BUILDER_FROM_NAME = "Moses at Verilay"


def _send_mail(to, subject, body, reply_to=None, personal=False):
    """Best-effort email through Verilay's ZeptoMail relay. Returns True/False, never raises."""
    try:
        import verilay_notify as notify
        if not notify.configured() or not to:
            print("[directory] email not configured; nothing sent", flush=True)
            return False
    except Exception:
        return False
    senders = [(BUILDER_FROM, f"{BUILDER_FROM_NAME} <{BUILDER_FROM}>")] if personal else []
    senders.append((notify.FROM_ADDRESS, f"Verilay <{notify.FROM_ADDRESS}>"))
    for envelope, header in senders:
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = _clean(subject, 150)
            msg["From"] = header
            msg["To"] = to
            if reply_to:
                msg["Reply-To"] = reply_to
            with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
                server.login("emailapikey", notify.ZEPTOMAIL_TOKEN)
                server.sendmail(envelope, [to], msg.as_string())
            return True
        except Exception as e:
            print(f"[directory] email from {envelope} failed: {e}", flush=True)
    return False


def _send_review_alert(row):
    """Email Moses that a listing is waiting."""
    try:
        import verilay_notify as notify
        to = notify.MONITORING_INTEREST_NOTIFY_EMAIL
    except Exception:
        return False
    lines = [
        "A new app listing is waiting for your review.", "",
        f"App: {row.get('app_name')}",
        f"What it does: {row.get('tagline')}",
        f"Web address: {row.get('app_url')}",
        f"Repository: github.com/{row.get('repo')}",
        f"Built with: {row.get('built_with')} (the scan guessed: {row.get('detected_with') or 'not recorded'})",
        f"Builder: {row.get('builder_name')}",
        f"Confidence stamp: {'yes' if row.get('stamped') else 'no'}",
        "", "Approve or hide it: https://verilay.dev/apps/review", "", "— Verilay",
    ]
    return _send_mail(to, f"New app listing: {row.get('app_name')}", "\n".join(_clean(x, 300) for x in lines))


def _hello(listing):
    first = _clean(listing.get("builder_name"), 60).split(" ")[0] if listing.get("builder_name") else ""
    return f"Hi {first}," if first else "Hi,"


def contact_email(listing, visitor_email, message):
    """(subject, body) of the email that passes a visitor's message to the builder."""
    name = _clean(listing.get("app_name"), 60)
    quoted = "\n".join("> " + line for line in message.split("\n"))
    body = (f"{_hello(listing)}\n\n"
            f"Someone found {name} in the Verilay app directory and wrote to you:\n\n"
            f"{quoted}\n\n"
            f"From: {visitor_email}\n\n"
            f"Just press Reply to answer them directly. Your own email address is never shown on the directory.\n\n"
            f"Moses\n"
            f"Verilay · https://verilay.dev{app_path(listing)}\n")
    return f"New message about {name} from the Verilay app directory", body


def approval_email(listing, now=None):
    """(subject, body) of the email sent to a builder when their listing is approved."""
    name = _clean(listing.get("app_name"), 60)
    url = "https://verilay.dev" + app_path(listing)
    if stamp_state(listing, now) == "fresh":
        date = _date_text(listing.get("checked_at"))
        until = _date_text((_parse_time(listing["checked_at"]) + _dt.timedelta(days=STAMP_DAYS)).isoformat())
        stamp = (f"It carries the “Checked by Verilay” stamp, because its scan on {date} found no "
                 f"critical issues.\n\n"
                 f"You can put the stamp on your own site too. The code to copy is on your app's page:\n"
                 f"{url}#stamp\n\n"
                 f"The stamp keeps itself up to date and stays current until {until}. Run a fresh free scan at "
                 f"https://verilay.dev before then, list it again, and it renews.\n\n")
    else:
        stamp = ("It is listed without the “Checked by Verilay” stamp for now. To earn it, fix the issues "
                 "from your scan, run a fresh free scan at https://verilay.dev and choose “List my app” "
                 "again.\n\n")
    body = (f"{_hello(listing)}\n\n"
            f"Good news: {name} is now live in the Verilay app directory:\n{url}\n\n"
            f"{stamp}"
            f"When someone uses “Contact the builder” on your page, their message comes to this email "
            f"address. Your address is never shown on the site, and you can reply to them directly.\n\n"
            f"If anything on your listing needs changing, just reply to this email.\n\n"
            f"Thanks for building something and sharing it,\n"
            f"Moses\n"
            f"Founder, Verilay\n")
    return f"{name} is now listed on Verilay", body


def _send_approval(listing):
    to = listing.get("contact") or ""
    if not _EMAIL.match(to) or to.lower() == BUILDER_FROM:
        return False  # Moses's own apps: no need to email himself
    subject, body = approval_email(listing)
    return _send_mail(to, subject, body, personal=True)


def _send_contact(listing, visitor_email, message, contact_id=None):
    """Pass a visitor's message to the builder. The visitor is the Reply-To, so the builder answers
    them directly and the builder's own address is never shown to anyone."""
    to = listing.get("contact") or ""
    if not _EMAIL.match(to):
        return False
    subject, body = contact_email(listing, visitor_email, message)
    sent = _send_mail(to, subject, body, reply_to=visitor_email, personal=True)
    sb = _deps["sb"]
    if sent and contact_id and sb is not None:
        try:
            sb.table(CONTACTS).update({"emailed": True}).eq("id", contact_id).execute()
        except Exception:
            pass
    return sent


# ── Storage ───────────────────────────────────────────────────────────────────

def _free_slug(sb, base, repo):
    """`base`, or base-2, base-3 ... — the first one no other app uses."""
    for n in range(1, 30):
        cand = base if n == 1 else f"{base}-{n}"
        used = sb.table(TABLE).select("repo").eq("slug", cand).limit(1).execute().data or []
        if not used or used[0].get("repo") == repo:
            return cand
    return f"{base}-{secrets.token_hex(3)}"


def save_listing(row):
    """Insert or update the listing for row['repo']. Returns 'new', 'updated' or 'none'."""
    sb = _deps["sb"]
    if sb is None:
        return "none"
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    try:
        existing = sb.table(TABLE).select("id,slug").eq("repo", row["repo"]).limit(1).execute().data or []
        if existing:
            # Keep the app's address once it has one, so stamps already on people's sites keep working.
            slug = existing[0].get("slug") or _free_slug(sb, slugify(row.get("app_name")), row["repo"])
            sb.table(TABLE).update(dict(row, slug=slug, status="pending", updated_at=now)) \
                .eq("id", existing[0]["id"]).execute()
            return "updated"
        slug = _free_slug(sb, slugify(row.get("app_name")), row["repo"])
        sb.table(TABLE).insert(dict(row, slug=slug, status="pending", updated_at=now)).execute()
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


def approved_by_slug(slug):
    sb = _deps["sb"]
    if sb is None or not _SLUG.match(slug or ""):
        return None
    try:
        rows = sb.table(TABLE).select("*").eq("slug", slug).eq("status", "approved").limit(1).execute().data or []
    except Exception as e:
        print(f"[directory] lookup failed for {slug}: {e}", flush=True)
        return None
    return rows[0] if rows else None


def sitemap_entries():
    """(url, changefreq, priority) for every approved app page, for /sitemap.xml."""
    return [("https://verilay.dev" + app_path(r), "weekly", "0.6") for r in approved_listings() if app_path(r)]


# ── Listing (from the results page) ───────────────────────────────────────────

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


# ── The directory page ────────────────────────────────────────────────────────

_STYLE = """<style>
.wrap{max-width:860px}
.dir-tools{display:flex;gap:8px;flex-wrap:wrap;margin:1.25rem 0 1rem}
.dir-tools input[type=search]{flex:1 1 240px;padding:10px 12px;font-size:15px;border:1px solid #e8e6e0;border-radius:8px;font-family:inherit}
.dir-tools select{width:auto;flex:0 1 auto}
.dir-check{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:500;margin:0;padding:0 4px;cursor:pointer}
.dir-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:.75rem}
.app-card{background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem;display:flex;flex-direction:column;gap:.5rem;min-width:0}
.app-name{font-weight:700;font-size:16px;color:#1a1917;overflow-wrap:anywhere;text-decoration:none}
.app-by{font-size:12px;color:#6b6966;margin-top:-.3rem;overflow-wrap:anywhere}
.app-line{font-size:13px;color:#4a4846;line-height:1.55;overflow-wrap:anywhere}
.chips{display:flex;gap:5px;flex-wrap:wrap}
.chip{font-size:11px;padding:2px 9px;border-radius:20px;background:#f0efec;color:#4a4846}
.stamp{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:20px;background:#E1F5EE;color:#085041;align-self:flex-start;text-decoration:none}
.stamp-old{background:#f0efec;color:#6b6966;font-weight:500}
.card-stamp{display:block;align-self:flex-start;line-height:0;margin:-.15rem 0 -.1rem -.2rem}
.app-links{display:flex;gap:12px;flex-wrap:wrap;font-size:13px;margin-top:auto;padding-top:.25rem}
.dir-empty{background:#fff;border:0.5px dashed #c9c7c2;border-radius:12px;padding:1.5rem;text-align:center;color:#6b6966;font-size:14px}
</style>"""


def _chips(r):
    chips = [r.get("built_with"), CATEGORIES.get(r.get("category"), "")]  # no price: the app's own site shows that
    if r.get("beta_testers"):
        chips.append("Looking for beta testers")
    if r.get("custom_work"):
        chips.append("Open to custom work")
    return "".join(f'<span class="chip">{_esc(c)}</span>' for c in chips if c)


def _card(r):
    fresh = stamp_is_fresh(r)
    date = _date_text(r.get("checked_at"))
    page = app_path(r)
    if stamp_state(r) != "none":
        # The same stamp makers put on their sites, drawn inline (no extra request) at a card-friendly size.
        art = stamp_svg(r).replace(f'width="{_STAMP_W}" height="{_STAMP_H}"', 'width="152" height="69"', 1)
        tag = "a" if page else "span"
        href = f' href="{_esc(page)}"' if page else ""
        tip = (f"No critical issues found in what Verilay checked on {date}. A confidence stamp, not a guarantee "
               f"of security." if fresh else f"Checked on {date}; the stamp has expired until the app is checked again.")
        stamp = f'<{tag} class="card-stamp"{href} title="{_esc(tip)}">{art}</{tag}>'
    else:
        stamp = ""
    rel = "noopener" if fresh else "nofollow ugc noopener"
    repo = r.get("repo") or ""
    name = _esc(r.get("app_name"))
    title = f'<a class="app-name" href="{_esc(page)}">{name}</a>' if page else f'<div class="app-name">{name}</div>'
    by = f'<div class="app-by">Built by {_esc(r.get("builder_name"))}</div>' if r.get("builder_name") else ""
    search = " ".join(str(x or "") for x in (r.get("app_name"), r.get("tagline"), r.get("built_with"),
                                              CATEGORIES.get(r.get("category"), ""), r.get("builder_name"))).lower()
    return (
        f'<div class="app-card" data-search="{_esc(search)}" data-built="{_esc(r.get("built_with"))}" '
        f'data-cat="{_esc(r.get("category"))}" data-checked="{"1" if fresh else "0"}">'
        f'{title}{by}'
        f'<div class="app-line">{_esc(r.get("tagline"))}</div>'
        f'{stamp}<div class="chips">{_chips(r)}</div>'
        f'<div class="app-links">'
        f'<a href="{_esc(r.get("app_url"))}" target="_blank" rel="{rel}">Open the app &#x2197;</a>'
        + (f'<a href="{_esc(page)}#contact">Contact the builder</a>' if page else "")
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
    <strong>Checked by Verilay</strong> stamp, and your app's page here gives you a stamp to put on your own site.</p>
    <a class="btn" href="/">Run a free scan</a>
  </div>
  <p class="note"><strong>What the stamp means:</strong> on the date shown, a Verilay scan of the app's code
  found no critical issues and graded it A or B. It is a confidence stamp for new builders, not a security
  guarantee or a penetration test, and it fades after {STAMP_DAYS} days unless the app is checked again.
  Listings are written by the people who built the apps and are reviewed before they appear.</p>
"""
    return _page("Apps built with AI tools", body + (_FILTER_JS if rows else ""))


# ── The stamp makers put on their own sites ───────────────────────────────────
# Drawn live from the listing every time it is shown, so it can never claim more than is true right
# now: fresh check → green "CHECKED"; older than STAMP_DAYS → amber "EXPIRED"; not listed,
# hidden, or no stamp → "No current check". It contains no text typed by a maker, only Verilay's own
# wording and a date, and always links back to the app's page on verilay.dev.

_STAMP_W, _STAMP_H = 190, 86


def stamp_svg(row, dark=False, now=None):
    """The ink stamp (Moses's choice, 2026-10-16): a double-bordered rubber stamp, tilted as if pressed.
    Each state has its own colour AND its own symbol, so they tell apart at a glance even for someone who
    can't see colour well: green with a tick when the check is current, amber with a clock when it has
    expired, grey with no symbol when there is no current check. The corners stay transparent, so it sits
    on any background."""
    state = stamp_state(row, now)
    date = _date_text(row.get("checked_at")).upper() if row else ""
    if dark:
        paper, green, amber, grey = "#1f1e1c", "#5DCAA5", "#EF9F27", "#9c9a92"
        deep = {green: "#9FE1CB", amber: "#FAC775", grey: "#D3D1C7"}
    else:
        paper, green, amber, grey = "#ffffff", "#0F6E56", "#A35F00", "#6b6966"
        deep = {green: "#04342C", amber: "#633806", grey: "#2C2C2A"}
    if state == "fresh":
        ink, label, line2, line3 = green, "CHECKED", "NO CRITICAL ISSUES", f"VERILAY · {date}"
        # A drawn tick, not a text character, so it looks the same on every device.
        icon = f'<path d="M33 31 L38.5 36.5 L48 26" fill="none" stroke="{ink}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
    elif state == "expired":
        ink, label, line2, line3 = amber, "EXPIRED", "DUE FOR A FRESH CHECK", f"VERILAY · {date}"
        icon = (f'<circle cx="40.5" cy="31" r="7.5" fill="none" stroke="{ink}" stroke-width="2.2"/>'
                f'<path d="M40.5 26.5 V31 L43.5 33" fill="none" stroke="{ink}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>')
    else:
        ink, label, line2, line3 = grey, "VERILAY", "NO CURRENT CHECK", "VERILAY.DEV/APPS"
        icon = ""
    alt = {"fresh": f"Checked by Verilay on {date.title()}: no critical issues found",
           "expired": f"Verilay check from {date.title()} has expired",
           "none": "No current Verilay check"}[state]
    font = "'Courier New',Courier,monospace"
    label_x = 104 if icon else 95
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_STAMP_W}" height="{_STAMP_H}" '
        f'viewBox="0 0 {_STAMP_W} {_STAMP_H}" role="img" aria-label="{_esc(alt)}">'
        f'<title>{_esc(alt)}</title>'
        f'<g transform="rotate(-4 95 43)">'
        f'<rect x="6" y="8" width="178" height="70" rx="6" fill="{paper}" stroke="{ink}" stroke-width="2.5"/>'
        f'<rect x="11" y="13" width="168" height="60" rx="3" fill="none" stroke="{ink}" stroke-width="1" '
        f'stroke-dasharray="3 2.5"/>'
        f'{icon}'
        f'<g font-family="{font}" font-weight="700" fill="{ink}" text-anchor="middle">'
        f'<text x="{label_x}" y="38" font-size="20" letter-spacing="3">{_esc(label)}</text>'
        f'<text x="95" y="53" font-size="10">{_esc(line2)}</text>'
        f'<text x="95" y="67" font-size="11" letter-spacing="0.5" fill="{deep[ink]}">{_esc(line3)}</text>'
        f'</g></g></svg>'
    )


@bp.route("/apps/<slug>/stamp.svg")
def stamp_image(slug):
    svg = stamp_svg(approved_by_slug(slug), dark=request.args.get("theme") == "dark")
    return Response(svg, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"})


_COPY_JS = """<script>
document.querySelectorAll('[data-copy]').forEach(function(btn){
  btn.addEventListener('click',function(){
    var t=document.getElementById(btn.getAttribute('data-copy'));
    function done(){btn.textContent='Copied';setTimeout(function(){btn.textContent='Copy';},1800);}
    if(navigator.clipboard){navigator.clipboard.writeText(t.value).then(done,function(){t.select();});}
    else{t.select();try{document.execCommand('copy');done();}catch(e){}}
  });
});
</script>"""


def _code_box(box_id, label, code):
    return (f'<label for="{box_id}">{label}</label><div style="display:flex;gap:6px;align-items:flex-start;'
            f'margin-bottom:.9rem"><textarea id="{box_id}" rows="3" readonly style="font-family:ui-monospace,'
            f'Consolas,monospace;font-size:12px">{_esc(code)}</textarea><button type="button" class="btn '
            f'btn-quiet" data-copy="{box_id}" style="padding:8px 14px;font-size:13px">Copy</button></div>')


# ── Each app's own page: check status, contact form, stamp code ───────────────

@bp.route("/apps/<slug>")
def app_page(slug):
    row = approved_by_slug(slug)
    if not row:
        body = ('<div class="eyebrow">App directory</div><h1>Not in the directory</h1>'
                '<p>There is no current listing at this address. It may have been removed, or it was never listed.</p>'
                '<p><a class="btn" href="/apps">See apps built with AI tools</a></p>')
        resp = _page("Not in the directory", body, robots="noindex,follow")
        resp.status_code = 404
        return resp
    state = stamp_state(row)
    date = _date_text(row.get("checked_at"))
    page = app_path(row)
    base = "https://verilay.dev" + page
    img = base + "/stamp.svg"
    builder = _esc(row.get("builder_name") or "the builder")
    if state == "fresh":
        until = _date_text((_parse_time(row["checked_at"]) + _dt.timedelta(days=STAMP_DAYS)).isoformat())
        status = (f'<div class="ok">On {_esc(date)}, a Verilay scan of this app\'s code found <strong>no critical '
                  f'issues</strong> and graded it A or B. The stamp stays current until {_esc(until)} unless the app is '
                  f'checked again.</div>')
    elif state == "expired":
        status = (f'<div class="warn">This app was checked on {_esc(date)}, more than {STAMP_DAYS} days ago, so its '
                  f'stamp has expired until it is checked again.</div>')
    else:
        status = ""

    sent, err = request.args.get("sent"), _clean(request.args.get("err"), 160)
    banner = ""
    if sent:
        banner = f'<div class="ok">Thank you. Your message has been passed to {builder}, who can reply to you by email.</div>'
    if err:
        banner += f'<div class="err">{_esc(err)}</div>'
    contact = (
        f'<div class="card" id="contact" style="margin-top:1.25rem"><h2 style="margin-top:0">Contact {builder}</h2>'
        f'<p>Ask a question, report a problem or talk about custom work. Your message is emailed to {builder}, who '
        f'can reply to you directly. Their email address is never shown here.</p>{banner}'
        f'<form method="POST" action="{_esc(page)}/contact">'
        f'<label for="c-email">Your email</label>'
        f'<input type="email" id="c-email" name="email" required maxlength="254" autocomplete="email" placeholder="you@example.com">'
        f'<div style="height:.75rem"></div>'
        f'<label for="c-msg">Your message</label>'
        f'<textarea id="c-msg" name="message" rows="4" required minlength="10" maxlength="1000"></textarea>'
        f'<div style="position:absolute;left:-9999px" aria-hidden="true"><label>Website'
        f'<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>'
        f'<p class="note" style="margin:.5rem 0 .75rem">Verilay keeps your email and message so it can see which '
        f'apps people are interested in. It is never shown publicly. See the <a href="/privacy">privacy policy</a>.</p>'
        f'<button class="btn" type="submit">Send message</button></form></div>'
    )

    embed = ""
    if state == "fresh":
        html_light = (f'<a href="{base}" target="_blank" rel="noopener"><img src="{img}" '
                      f'alt="Checked by Verilay" width="{_STAMP_W}" height="{_STAMP_H}"></a>')
        html_dark = html_light.replace(img, img + "?theme=dark")
        md = f"[![Checked by Verilay]({img})]({base})"
        embed = (
            '<div class="card" id="stamp" style="margin-top:1.25rem"><h2 style="margin-top:0">Built this app? Add the stamp '
            'to your site</h2><p>Paste one of these into your site, for example its footer (in Lovable, Bolt or '
            'Replit, ask the AI to &ldquo;add this HTML to the footer&rdquo;). The stamp keeps itself up to date: '
            'if the check expires, it says so.</p>'
            f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:.25rem 0 1rem">'
            f'<img src="{_esc(page)}/stamp.svg" alt="Light stamp" width="{_STAMP_W}" height="{_STAMP_H}">'
            f'<img src="{_esc(page)}/stamp.svg?theme=dark" alt="Dark stamp" width="{_STAMP_W}" height="{_STAMP_H}" '
            f'style="background:#2c2c2a;border-radius:10px;padding:4px"></div>'
            + _code_box("code-light", "HTML, for a light background", html_light)
            + _code_box("code-dark", "HTML, for a dark background", html_dark)
            + _code_box("code-md", "Markdown, for a GitHub README", md)
            + '</div>')

    rel = "noopener" if state == "fresh" else "nofollow ugc noopener"
    stamp_img = (f'<p style="margin:1rem 0"><img src="{_esc(page)}/stamp.svg" alt="Verilay stamp" '
                 f'width="{_STAMP_W}" height="{_STAMP_H}"></p>') if state != "none" else ""
    body = (
        f'{_STYLE}<div class="eyebrow"><a href="/apps" style="text-decoration:none">App directory</a></div>'
        f'<h1>{_esc(row.get("app_name"))}</h1>'
        + (f'<p class="note" style="margin-top:-.25rem">Built by {_esc(row.get("builder_name"))}</p>'
           if row.get("builder_name") else "")
        + f'<p>{_esc(row.get("tagline"))}</p><div class="chips" style="margin-bottom:.5rem">{_chips(row)}</div>'
        f'{stamp_img}{status}'
        f'<p style="margin-top:1rem"><a class="btn" href="{_esc(row.get("app_url"))}" target="_blank" rel="{rel}">'
        f'Open the app &#x2197;</a> &nbsp;<a href="#contact">Contact {builder}</a></p>'
        f'{contact}{embed}'
        f'<p class="note" style="margin-top:1.25rem"><strong>What the stamp means:</strong> a Verilay scan of the '
        f'app\'s code found no critical issues and graded it A or B on the date shown. It is a confidence stamp '
        f'for new builders, not a security guarantee or a penetration test. Listings are written by the people '
        f'who built the apps. <a href="/">Check your own app free</a>.</p>'
    )
    return _page(f"{row.get('app_name')} - built with {row.get('built_with') or 'AI'}", body + (_COPY_JS if embed else ""))


@bp.route("/apps/<slug>/contact", methods=["POST"])
def contact_builder(slug):
    row = approved_by_slug(slug)
    if not row:
        return redirect("/apps")
    page = app_path(row)

    def back(err=""):
        return redirect(page + ("?err=" + urllib.parse.quote(err) if err else "?sent=1") + "#contact")

    if request.form.get("website"):  # bot: look like success, send and store nothing
        return back()
    email = _clean(request.form.get("email"), 254).lower()
    message = str(request.form.get("message") or "").replace("\r\n", "\n").strip()[:1000]
    message = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", message)
    if not _EMAIL.match(email):
        return back("Please enter a valid email address, so the builder can reply.")
    if len(message) < 10:
        return back("Please write a slightly longer message (at least 10 characters).")
    if not _hit_ok(_CONTACT_HITS, "ip:" + _deps["get_ip"](), 5, 3600) or \
            not _hit_ok(_CONTACT_HITS, "app:" + slug, 30, 86400):
        return back("Too many messages just now. Please try again later.")
    contact_id = None
    sb = _deps["sb"]
    if sb is not None:
        try:
            res = sb.table(CONTACTS).insert({"listing_id": row.get("id"), "app_name": row.get("app_name"),
                                             "visitor_email": email, "message": message,
                                             "emailed": False}).execute()
            contact_id = (res.data or [{}])[0].get("id")
        except Exception as e:
            print(f"[directory] could not store contact message: {e}", flush=True)
    if _cap_ok(_MAIL_HITS, 60):
        threading.Thread(target=_send_contact, args=(row, email, message, contact_id), daemon=True).start()
    else:
        print("[directory] contact email cap reached this hour; message stored, not emailed", flush=True)
    return back()


# ── Moses's review page ───────────────────────────────────────────────────────

def _same_origin():
    """Admin buttons must be pressed on this site, not on another page that posts here."""
    src = request.headers.get("Origin") or request.headers.get("Referer") or ""
    try:
        return urllib.parse.urlsplit(src).netloc == request.host
    except Exception:
        return False


def _messages_html(sb):
    try:
        msgs = sb.table(CONTACTS).select("*").order("created_at", desc=True).limit(50).execute().data or []
    except Exception:
        return ('<p class="note">Messages to builders are not being kept yet. Run supabase_app_directory_v2.sql '
                'in Supabase.</p>')
    if not msgs:
        return '<p class="note">No messages yet.</p>'
    return "".join(
        f'<div class="card"><p class="note" style="margin:0">{_esc(_date_text(m.get("created_at")))} &middot; '
        f'<strong>{_esc(m.get("app_name"))}</strong> &middot; from {_esc(m.get("visitor_email"))} &middot; '
        f'{"emailed to the builder" if m.get("emailed") else "NOT emailed"}</p>'
        f'<p style="margin:.4rem 0 0;white-space:pre-wrap">{_esc(m.get("message"))}</p></div>'
        for m in msgs)


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
        page = app_path(r)
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
            f'Builder: {_esc(r.get("builder_name") or "-")} ({_esc(r.get("contact"))})<br>'
            f'Stamp: {"yes" if r.get("stamped") else "no"}'
            f' &middot; checked {_esc(_date_text(r.get("checked_at")) or "?")}'
            + (f' &middot; page <a href="{_esc(page)}" target="_blank" rel="noopener">{_esc(page)}</a>' if page else "")
            + f' &middot; scan report <a href="/report/{_esc(r.get("report_id"))}" target="_blank" rel="noopener">'
            f'{_esc(r.get("report_id"))}</a></p>'
            f'<form method="POST" action="/apps/review/{_esc(r.get("id"))}" '
            f'style="display:flex;gap:6px;flex-wrap:wrap;margin-top:.75rem">{buttons}</form></div>')
    pending = sum(1 for r in rows if (r.get("status") or "pending") == "pending")
    body = (f'<div class="eyebrow">Admin</div><h1>App listings to review</h1>'
            f'<p>{pending} waiting. Check the app is real, built with AI tools, and that the web address matches '
            f'the code. Only approved apps appear on <a href="/apps">/apps</a>.</p>'
            + (f'<div class="err">{_esc(problem)}</div>' if problem else "")
            + ("".join(items) or '<p class="note">No listings yet.</p>')
            + '<h2>Messages to builders</h2>'
            + (_messages_html(sb) if sb is not None else ""))
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
            before = sb.table(TABLE).select("*").eq("id", listing_id).limit(1).execute().data or []
            sb.table(TABLE).update({"status": status}).eq("id", listing_id).execute()
            # Tell the builder their app is live (once per approval, not on every click).
            if status == "approved" and before and before[0].get("status") != "approved":
                threading.Thread(target=_send_approval, args=(dict(before[0], status=status),), daemon=True).start()
        except Exception as e:
            print(f"[directory] review update failed: {e}", flush=True)
    return redirect("/apps/review")
