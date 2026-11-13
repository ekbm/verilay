"""
verilay_appcount.py: the "N apps analysed so far" figure on the homepage (2026-10-14).

The old figure was a running total that went up by one for every finished scan: the same app scanned ten times
counted ten times, and the owner's own apps and test scans counted too (of 467 saved reports, 143 were different
apps, and most scans were the owner's own or tests). Now the figure is the number of DIFFERENT apps, leaving out the
owner's own apps and known test repos. Scans are still saved and work exactly as before; only the public number
changes.

The count comes from a small database function (supabase_apps_analysed.sql). If it does not exist yet, or the
database fails, the old running total is shown instead, so the homepage never breaks. The answer is kept for 10
minutes so the homepage does not ask the database on every visit.

Leave more things out without a deploy: set VERILAY_COUNT_EXCLUDE_EXTRA on Railway to a comma-separated list
(patterns may use % as a wildcard, e.g. someone/%).
"""
import os
import threading
import time

CACHE_SECONDS = 600
FAIL_RETRY_SECONDS = 60

# The owner's own apps and well-known test targets. Matched case-insensitively against the saved repo name, which is
# "owner/name" for GitHub scans and the site name for URL scans. % is a wildcard.
DEFAULT_EXCLUDE = (
    "ekbm/%",
    "evident-ai.net", "www.evident-ai.net",
    "buildbook.au", "www.buildbook.au",
    "loginsight.com.au", "www.loginsight.com.au", "loginsight.app", "www.loginsight.app",
    "verilay.dev", "www.verilay.dev",
    "jobhiro.com.au", "www.jobhiro.com.au", "jobhiro.com", "www.jobhiro.com",
    "diychatbots.com", "www.diychatbots.com",
    "octocat/hello-world", "tj/commander.js",
    # Verilay's accuracy check (7 Nov 2026): its own test apps (uploaded as verilay-eval-*.zip) and the public practice
    # apps it scans on every run.
    "verilay-eval-%", "juice-shop/juice-shop", "owasp/nodegoat", "digininja/dvwa",
    "google.com", "www.google.com", "apple.com", "www.apple.com", "github.com", "www.github.com",
)

_lock = threading.Lock()
_cache = {"value": None, "at": 0.0, "failed_at": 0.0}


def exclude_patterns():
    extra = [p.strip().lower() for p in os.getenv("VERILAY_COUNT_EXCLUDE_EXTRA", "").split(",") if p.strip()]
    seen, out = set(), []
    for p in [p.lower() for p in DEFAULT_EXCLUDE] + extra:
        if p not in seen:
            seen.add(p); out.append(p)
    return out


def apps_analysed(sb, now=None):
    """The number of different apps analysed (own and test apps left out), or None when it cannot be worked out
    (no database, function not created yet, database error). Never raises."""
    if sb is None:
        return None
    now = now if now is not None else time.time()
    with _lock:
        if _cache["value"] is not None and now - _cache["at"] < CACHE_SECONDS:
            return _cache["value"]
        if _cache["failed_at"] and now - _cache["failed_at"] < FAIL_RETRY_SECONDS:
            return None
    try:
        res = sb.rpc("apps_analysed", {"exclude_patterns": exclude_patterns()}).execute()
        val = res.data
        if isinstance(val, list):
            val = val[0] if val else None
        if isinstance(val, dict):
            val = next(iter(val.values()), None)
        val = int(val)
        if val < 0:
            raise ValueError("negative count")
    except Exception as e:
        print(f"[appcount] using the old running total: {type(e).__name__}", flush=True)
        with _lock:
            _cache["failed_at"] = now
        return None
    with _lock:
        _cache.update(value=val, at=now, failed_at=0.0)
    return val


def reset_cache():
    with _lock:
        _cache.update(value=None, at=0.0, failed_at=0.0)
        _improved.update(value=None, at=0.0, failed_at=0.0)


# ── "N apps re-checked with a better grade" (2 Nov 2026) ─────────────────────────────────────────────────────────────
# Moses: show new visitors that Verilay helps, since few people say so openly. Each app counts ONCE, and only when a
# later scan of it graded better than the scan before (the saved report keeps the earlier grade as prev_score). The
# owner's own apps and test repos are left out, the same list as above. Shown on the homepage only once it reaches
# IMPROVED_MIN (a small number looks weaker than none); the admin always sees it.
GRADES = "ABCDF"
IMPROVED_MIN = 20
_improved = {"value": None, "at": 0.0, "failed_at": 0.0}


def _excluded(repo, patterns):
    import fnmatch
    r = (repo or "").strip().lower()
    return any(fnmatch.fnmatchcase(r, p.replace("%", "*")) for p in patterns)


def grade_went_up(before, after):
    """True when `after` is a better letter grade than `before` (A best, F worst)."""
    b, a = str(before or "").strip().upper()[:1], str(after or "").strip().upper()[:1]
    return bool(b and a and b in GRADES and a in GRADES and GRADES.index(a) < GRADES.index(b))


def count_improved(rows, patterns=None):
    """Different apps (by saved name, any case) with at least one re-scan that graded better than the one before."""
    patterns = exclude_patterns() if patterns is None else patterns
    apps = set()
    for r in rows or []:
        repo = str((r or {}).get("repo") or "").strip().lower()
        if repo and not _excluded(repo, patterns) and grade_went_up(r.get("prev"), r.get("score")):
            apps.add(repo)
    return len(apps)


def apps_improved(sb, now=None):
    """The number of apps re-checked with a better grade, or None when it cannot be worked out. Never raises."""
    if sb is None:
        return None
    now = now if now is not None else time.time()
    with _lock:
        if _improved["value"] is not None and now - _improved["at"] < CACHE_SECONDS:
            return _improved["value"]
        if _improved["failed_at"] and now - _improved["failed_at"] < FAIL_RETRY_SECONDS:
            return None
    try:
        # Every re-scan is read, page by page (13 Nov 2026: a single request returns at most 1,000 rows on Supabase,
        # so the old .limit(5000) would quietly have stopped counting once there were more re-scans than that).
        rows, start, page = [], 0, 1000
        while start < 200000:
            part = (sb.table("reports").select("repo,score,prev:data->>prev_score").not_.is_("data->>prev_score", "null")
                    .order("created_at", desc=True).range(start, start + page - 1).execute().data or [])
            rows += part
            if len(part) < page:
                break
            start += page
        val = count_improved(rows)
    except Exception as e:
        print(f"[appcount] apps improved not worked out: {type(e).__name__}", flush=True)
        with _lock:
            _improved["failed_at"] = now
        return None
    with _lock:
        _improved.update(value=val, at=now, failed_at=0.0)
    return val


def improved_for_homepage(sb):
    """The figure to show on the homepage, or "" while it is below the minimum (or unknown)."""
    n = apps_improved(sb)
    try:
        floor = int(os.getenv("VERILAY_IMPROVED_MIN", "") or IMPROVED_MIN)
    except ValueError:
        floor = IMPROVED_MIN
    return n if isinstance(n, int) and n >= max(1, floor) else ""
