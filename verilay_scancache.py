"""
verilay_scancache.py — reuse a recent free analysis of exactly the same code (2026-10-13).

Scanning the same public repo twice used to pay for the whole analysis twice (about five AI calls). Now, when the
repo's newest commit is the same and the analysis was made within 24 hours by the same version of Verilay's
rules, the earlier result is replayed: no new AI calls, an answer in seconds. Each visitor still gets a report of
their own (new id, new private key); only the analysis is reused.

Safety rules, all deliberate:
  * Only PUBLIC repositories are ever cached or served from the cache (the caller checks, and the admin's
    private scans never touch it).
  * The cache is written ONLY by the server, from a copy taken before the report is saved, into its own table
    (scan_cache). It is never read from a visitor's saved report, because a report's owner can edit it, and a
    cache built from editable data could be poisoned.
  * The key contains the repo, its newest commit, and ANALYSIS_VERSION (in app.py). Change a rule, a prompt or the
    scoring, bump ANALYSIS_VERSION, and every old entry is ignored at once.
  * Entries older than 24 hours are ignored (new advisories for packages appear daily); old rows are deleted.
  * It is entirely optional: if the table does not exist, the database fails, or VERILAY_SCAN_CACHE=0, every scan
    simply runs in full. Nothing here can make a scan fail.

Needs the table in supabase_scan_cache.sql (row-level protection ON, so the public key cannot read it).
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone

TTL_HOURS = 24
PURGE_AFTER_DAYS = 3
MAX_SNAPSHOT_BYTES = 1_500_000
_puts = 0
_lock = threading.Lock()


def enabled():
    return os.getenv("VERILAY_SCAN_CACHE", "1") != "0"


def make_key(repo, sha, version):
    return hashlib.sha256(f"{str(repo).lower()}|{sha}|{version}".encode("utf-8")).hexdigest()


def _parse(iso):
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def get(sb, key, now=None):
    """{"snapshot": {...}, "created_at": iso} or None. Never raises."""
    if sb is None or not enabled():
        return None
    try:
        res = sb.table("scan_cache").select("data,created_at").eq("cache_key", key).limit(1).execute()
        row = (res.data or [None])[0]
        if not row:
            return None
        created = _parse(row.get("created_at"))
        now = now or datetime.now(timezone.utc)
        if not created or now - created > timedelta(hours=TTL_HOURS):
            return None
        snap = row.get("data")
        if isinstance(snap, str):
            snap = json.loads(snap)
        if not isinstance(snap, dict) or not snap.get("partial") or not snap.get("s1"):
            return None
        return {"snapshot": snap, "created_at": row.get("created_at")}
    except Exception as e:
        print(f"[scancache] lookup skipped: {type(e).__name__}", flush=True)
        return None


def put(sb, key, repo, sha, version, snapshot):
    """Store a snapshot. Best effort: returns True/False, never raises."""
    global _puts
    if sb is None or not enabled():
        return False
    try:
        if len(json.dumps(snapshot, default=str)) > MAX_SNAPSHOT_BYTES:
            return False
        sb.table("scan_cache").upsert({"cache_key": key, "repo": str(repo).lower(), "repo_sha": sha,
                                       "analysis_version": version, "data": snapshot,
                                       "created_at": datetime.now(timezone.utc).isoformat()}).execute()
        with _lock:
            _puts += 1
            do_purge = (_puts % 20 == 0)
        if do_purge:   # now and then, delete rows nobody can use any more
            cutoff = (datetime.now(timezone.utc) - timedelta(days=PURGE_AFTER_DAYS)).isoformat()
            sb.table("scan_cache").delete().lt("created_at", cutoff).execute()
        return True
    except Exception as e:
        print(f"[scancache] store skipped: {type(e).__name__}", flush=True)
        return False
