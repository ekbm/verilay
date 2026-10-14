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
