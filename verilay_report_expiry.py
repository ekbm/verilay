"""
verilay_report_expiry.py: how long a free report's share link keeps working (2026-10-14).

Until now every saved report stayed readable by anyone holding its link for ever. Now a FREE report's link stops
working 90 days after the scan. Nothing is erased: the report is simply no longer served (the same "Report not
found" page a deleted report gets), so the rule is reversible and needs no cleanup job.

Never expires:
  * deep-scan reports (is_deep_scan) and any report owned by a signed-in account: those people paid for or signed
    in to keep them, and the privacy page promises they last as long as the account;
  * anything whose date is missing or unreadable (a bug here must never make reports vanish).

Change the number without a deploy: set VERILAY_REPORT_DAYS on Railway (0 = reports never expire).
"""
import os
from datetime import datetime, timedelta, timezone

DEFAULT_DAYS = 90


def days():
    """How many days a free report's link works; 0 means never expire."""
    raw = os.getenv("VERILAY_REPORT_DAYS", "")
    try:
        n = int(raw) if str(raw).strip() != "" else DEFAULT_DAYS
    except ValueError:
        return DEFAULT_DAYS
    return n if n >= 0 else DEFAULT_DAYS


PRIVATE_DEFAULT_DAYS = 30


def private_days():
    """How many days a PRIVATE report (private-repository beta) lasts. Never 0: a private report always expires."""
    try:
        n = int(os.getenv("VERILAY_PRIVATE_REPORT_DAYS", "").strip())
        return n if 1 <= n <= 365 else PRIVATE_DEFAULT_DAYS
    except ValueError:
        return PRIVATE_DEFAULT_DAYS


def _parse(ts):
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def sample_ids():
    """The ids of the example reports shown on the deep scan page (VERILAY_SAMPLE_REPORT_ID, the deep one, and
    VERILAY_SAMPLE_FREE_REPORT_ID, the free one). Their links must keep working, so they never expire."""
    out = set()
    for name in ("VERILAY_SAMPLE_REPORT_ID", "VERILAY_SAMPLE_FREE_REPORT_ID"):
        v = os.getenv(name, "").strip().lower()
        if len(v) == 12 and all(ch in "0123456789abcdef" for ch in v):
            out.add(v)
    return out


def expires_at(created_at, data, owner, report_id=None):
    """The moment this report's link stops working, or None when it never does."""
    private = isinstance(data, dict) and bool(data.get("private"))
    n = private_days() if private else days()
    if (not private) and (n == 0 or owner or (isinstance(data, dict) and data.get("is_deep_scan"))):
        return None
    if report_id and str(report_id).lower() in sample_ids():
        return None
    created = _parse(created_at)
    if created is None:
        return None
    return created + timedelta(days=n)


def is_expired(created_at, data, owner, now=None, report_id=None):
    end = expires_at(created_at, data, owner, report_id)
    if end is None:
        return False
    return (now or datetime.now(timezone.utc)) >= end


def until_text(created_at, data, owner, report_id=None):
    """'12 Jan 2027' for a report that will expire, else ''."""
    end = expires_at(created_at, data, owner, report_id)
    return end.astimezone(timezone.utc).strftime("%d %b %Y") if end else ""
