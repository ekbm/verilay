"""
verilay_deepwatch.py — "should you run a deep scan?" for the apps the monitor watches (2026-10-13).

The daily monitor only does a free-scan-sized check, so it cannot see everything a deep scan finds. Instead of
guessing from the AI sample (whose findings change from run to run), it recommends a deep scan on STEADY signals:

  NEW      a new serious finding from the fixed rules since the last check (a critical exposed key, a critical or
           high vulnerable package that ships to users, a clear-cut access problem). Stays until a deep scan
           newer than the finding has been run.
  NEVER    no deep scan has ever been run on this app.
  CHANGED  since the last deep scan: 3 or more changes that touch login, sessions, tokens, the database, package
           lists, payments or settings files, OR 30 or more changes of any kind.
  OLD      the last deep scan is 30 days old or more AND the code has changed since.

Quiet period: within 7 days of a deep scan only NEW can fire, so a recommendation never appears straight after
you have just run one.

The same rules apply to every app for now. Custom rules per app are meant to be a later, paid option: that is why
every number lives in the constants below and nowhere else.

Everything here is best effort and never raises: a failure means "no recommendation this time", never a failed
check. Nothing in this module is public; the output is only for the admin page and the admin's email.
"""
import re
from datetime import datetime, timezone

import requests

# ── The rules (the same for every app) ───────────────────────────────────────
DEEP_SCAN_MAX_AGE_DAYS = 30        # OLD: deep scan this old, and code changed since
QUIET_DAYS_AFTER_DEEP_SCAN = 7     # only NEW may fire this soon after a deep scan
MIN_COMMITS_WITH_SENSITIVE = 3     # CHANGED: this many changes, at least one touching a sensitive file
MIN_COMMITS_ANY = 30               # CHANGED: this many changes of any kind
GITHUB_API = "https://api.github.com"
GITHUB_TIMEOUT = 15
MAX_TITLES = 10

# Plain-English categories of "files that matter for security". Generic folders like server/ or src/ are NOT
# listed: in an active app nearly every change touches them, which would make the signal useless.
_CATEGORIES = [
    # Words must start a file or folder name ("auth-db.ts", "email-auth.ts", "emailAuth.ts"), so "author" and
    # "tokenizer" do not count.
    ("login, sessions or tokens", [
        re.compile(r"(^|[/_.\-])(auth(?!or)|logins?|logout|signin|signup|sessions?|passport|oauth|jwt|passwords?|tokens?(?!iz)|permissions?|rbac|credentials?)", re.I),
        re.compile(r"[a-z0-9](Auth(?!or)|Login|Logout|SignIn|SignUp|Session|Passport|OAuth|Jwt|Password|Token(?!iz)|Permission|Credential)")]),
    ("the database", [re.compile(r"(migrations?/|\.sql$|schema|drizzle|prisma/|supabase/)", re.I)]),
    ("packages", [re.compile(r"(^|/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements\.txt|pyproject\.toml|poetry\.lock|pipfile)$", re.I)]),
    ("payments", [re.compile(r"(stripe|billing|payment|checkout|subscription|webhook)", re.I)]),
    ("settings", [re.compile(r"((^|/)\.env|dockerfile|docker-compose|(^|/)\.replit$|config\.(ts|js|toml|ya?ml)$)", re.I)]),
]
_IGNORE = re.compile(r"(^|/)(tests?|__tests__|docs?|assets|attached_assets|public|images|static)/|\.(md|txt|png|jpe?g|gif|svg|ico|webp|pdf|map|snap)$|\.(test|spec)\.", re.I)


def categorise(filenames):
    """({category: [files]}, total_sensitive) for the files that matter for security."""
    found = {}
    for name in filenames or []:
        is_package_list = any(rx.search(name) for rx in _CATEGORIES[2][1])
        if _IGNORE.search(name) and not is_package_list:
            continue
        for label, rxs in _CATEGORIES:
            if any(rx.search(name) for rx in rxs):
                found.setdefault(label, []).append(name)
                break
    return found, sum(len(v) for v in found.values())


# ── GitHub (read only, best effort) ──────────────────────────────────────────

def _gh(path, token, params=None):
    try:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "verilay-monitor"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = requests.get(GITHUB_API + path, headers=headers, params=params or {}, timeout=GITHUB_TIMEOUT)
        if r.status_code != 200:
            print(f"[deepwatch] GitHub {path} -> {r.status_code}", flush=True)
            return None
        return r.json()
    except Exception as e:
        print(f"[deepwatch] GitHub {path} failed: {type(e).__name__}", flush=True)
        return None


def _commit_info(data):
    try:
        c = data[0]
        return {"sha": c["sha"], "date": c["commit"]["committer"]["date"]}
    except Exception:
        return None


def head_info(owner, repo, token):
    """{"sha", "date"} of the newest commit on the default branch, or None."""
    return _commit_info(_gh(f"/repos/{owner}/{repo}/commits", token, {"per_page": 1}))


def sha_before(owner, repo, token, iso):
    """The newest commit made at or before `iso` (used for deep scans that did not record their commit)."""
    return _commit_info(_gh(f"/repos/{owner}/{repo}/commits", token, {"per_page": 1, "until": iso}))


def compare(owner, repo, token, base_sha, head_sha):
    """{"commits": n, "files": [names]} between two commits, or None."""
    if base_sha and head_sha and base_sha == head_sha:
        return {"commits": 0, "files": []}
    d = _gh(f"/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}", token)
    if not isinstance(d, dict):
        return None
    try:
        return {"commits": int(d.get("ahead_by") or 0), "files": [f.get("filename", "") for f in (d.get("files") or [])]}
    except Exception:
        return None


# ── The last deep scan of an app ─────────────────────────────────────────────

def _like_escape(s):
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def last_deep_scan(sb, repo):
    """The newest saved deep-scan report for this repo: {"id","created_at","grade","sha"}; None when there is
    none; the string "unknown" when the lookup itself failed (so we never claim 'never' by mistake)."""
    try:
        rows = (sb.table("reports")
                  .select("id,created_at,score,is_deep:data->>is_deep_scan,sha:data->>repo_sha")
                  .ilike("repo", _like_escape(repo))
                  .order("created_at", desc=True).limit(40).execute().data) or []
    except Exception as e:
        print(f"[deepwatch] last deep scan lookup failed: {type(e).__name__}", flush=True)
        return "unknown"
    for r in rows:
        if str(r.get("is_deep")).lower() == "true":
            return {"id": r.get("id"), "created_at": r.get("created_at"), "grade": r.get("score") or "", "sha": r.get("sha") or None}
    return None


def _parse(iso):
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ── The decision (pure: no network, easy to test) ────────────────────────────

def evaluate(now, last_deep, change, new_serious, prev=None):
    """Returns {"active": bool, "reasons": [{"code","text"}], "signature", "since", "new_serious", "emailed_signature"}.

    last_deep: None (never), "unknown" (lookup failed) or the dict from last_deep_scan().
    change:    None (unknown) or {"commits": n, "files": [names]} since that deep scan.
    new_serious: titles of serious findings that appeared in THIS check.
    prev:      the previous recommendation, so NEW persists and emails are not repeated."""
    prev = prev or {}
    deep_dt = _parse(last_deep.get("created_at")) if isinstance(last_deep, dict) else None

    # NEW persists until a deep scan newer than when it first appeared has been run.
    carried = list(prev.get("new_serious") or [])
    since_prev = _parse(prev.get("since"))
    if carried and since_prev and deep_dt and deep_dt > since_prev:
        carried = []
    serious = []
    for t in carried + list(new_serious or []):
        if t and t not in serious:
            serious.append(t)
    serious = serious[:MAX_TITLES]

    reasons = []
    if serious:
        n = len(serious)
        reasons.append({"code": "NEW", "text": f"{n} new serious finding{'s' if n != 1 else ''} appeared since the last check "
                                               "(exposed keys, vulnerable packages or access problems)."})
    if last_deep is None:
        reasons.append({"code": "NEVER", "text": "No deep scan has been run on this app yet."})
    elif isinstance(last_deep, dict) and deep_dt:
        age_days = (now - deep_dt).days
        quiet = age_days < QUIET_DAYS_AFTER_DEEP_SCAN
        if change is not None and not quiet:
            commits = int(change.get("commits") or 0)
            cats, n_sensitive = categorise(change.get("files"))
            when = deep_dt.strftime("%d %b %Y")
            if n_sensitive >= 1 and commits >= MIN_COMMITS_WITH_SENSITIVE:
                about = ", ".join(sorted(cats))
                reasons.append({"code": "CHANGED", "text": f"{commits} changes since the last deep scan ({when}), including files about {about}."})
            elif commits >= MIN_COMMITS_ANY:
                reasons.append({"code": "CHANGED", "text": f"{commits} changes since the last deep scan ({when})."})
            if age_days >= DEEP_SCAN_MAX_AGE_DAYS and commits >= 1:
                reasons.append({"code": "OLD", "text": f"The last deep scan was {age_days} days ago and the code has changed since."})

    codes = sorted(r["code"] for r in reasons)
    signature = "|".join(codes) + (f"|n={len(serious)}" if serious else "")
    active = bool(reasons)
    same = active and prev.get("active") and prev.get("signature") == signature
    return {
        "active": active, "reasons": reasons, "signature": signature if active else "",
        "since": (prev.get("since") if same else None) or (now.isoformat() if active else None),
        "new_serious": serious if active else [],
        "emailed_signature": prev.get("emailed_signature") if same else None,
    }


def should_email(rec):
    """True when a recommendation is active and this exact set of reasons has not been emailed yet."""
    return bool(rec and rec.get("active") and rec.get("signature") and rec.get("signature") != rec.get("emailed_signature"))
