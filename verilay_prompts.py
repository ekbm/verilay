"""
verilay_prompts.py - the A$2.99 fix-prompt unlock (from 1 Dec 2026).

Moses, 22 Nov 2026: scans, re-scans and every problem stay free; the ready-to-paste fix prompts for an app unlock for
A$2.99, for 7 days, re-scans included. The prompts are written on every scan anyway (they used to be hidden after the
first), so an unlock costs nothing extra in AI.

How it fits together:
  * When prompts are for sale, a free report keeps the full fixes in "locked_fixes" (never sent to a browser) and
    "top_fixes" holds copies without the prompt text ("stubs": title, why, how, effort, check-it-yourself stay free).
  * Paying goes through Stripe Checkout (hosted by Stripe; Verilay never sees a card). The WEBHOOK is the record of
    truth; the success page records the same session too (idempotent on stripe_session_id) so the buyer sees the
    prompts at once.
  * The unlock is for one app (app_key) for 7 days: the paid report shows its prompts to anyone with its link, and a
    re-scan of the same app shows them too, in the browser that paid (its Flask session remembers the Stripe session)
    or when signed in with the paying email.
"""
import os
import re
from datetime import datetime, timedelta, timezone

PRODUCT = "fix_prompts_v1"
PRICE_CENTS = int((os.getenv("FIX_PROMPTS_PRICE_CENTS", "299") or "299").strip())
CURRENCY = (os.getenv("FIX_PROMPTS_CURRENCY", "aud") or "aud").strip().lower()
UNLOCK_DAYS = 7
TAX_CODE = (os.getenv("DEEP_SCAN_TAX_CODE", "txcd_10103001") or "txcd_10103001").strip()
PROMPT_KEYS = ("general_prompt", "lovable_prompt", "replit_prompt", "fix_prompt")
TABLE = "prompt_unlocks"


def price_label():
    whole, cents = PRICE_CENTS // 100, PRICE_CENTS % 100
    return f"A${whole}" + (f".{cents:02d}" if cents else "") if CURRENCY == "aud" else f"{whole}.{cents:02d} {CURRENCY.upper()}"


def app_key(data, normalise_repo):
    """Which app a report is about: 'gh:owner/repo' for GitHub, 'zip:<name>' for a ZIP upload. None for anything else
    (a live address has no fix prompts)."""
    data = data or {}
    method = data.get("input_method")
    if method in ("github", "github_private"):
        canon = normalise_repo(str(data.get("repo") or ""))
        return f"gh:{canon}" if canon else None
    if method == "zip":
        name = re.sub(r"[^a-z0-9._-]+", "-", str(data.get("repo") or "").strip().lower()).strip("-")[:100]
        return f"zip:{name}" if name else None
    return None


def stub(fix):
    """A fix without its prompt text: what it is, why it matters and how to check it stay free."""
    if not isinstance(fix, dict):
        return fix
    out = {k: v for k, v in fix.items() if k not in PROMPT_KEYS}
    out["locked"] = True
    return out


def lock(fixes):
    """(stubs for the page, the full fixes to keep on the server)."""
    full = [f for f in (fixes or []) if isinstance(f, dict)]
    return [stub(f) for f in full], full


def _now():
    return datetime.now(timezone.utc)


def _active(row, now=None):
    if not row or (row.get("status") or "") != "active":
        return False
    try:
        exp = datetime.fromisoformat(str(row.get("expires_at")).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp > (now or _now())


def active_unlock(sb, key, session_ids=(), email=None, now=None):
    """An active unlock for this app that this visitor may use (their browser paid for it, or they are signed in
    with the paying email), else None. Never raises."""
    if sb is None or not key:
        return None
    sids = [s for s in (session_ids or []) if s]
    if not sids and not email:
        return None
    try:
        rows = sb.table(TABLE).select("*").eq("app_key", key).order("created_at", desc=True).limit(20).execute().data or []
    except Exception as e:
        print(f"[prompts] unlock lookup failed for {key}: {type(e).__name__}", flush=True)
        return None
    em = (email or "").strip().lower()
    for r in rows:
        if _active(r, now) and (r.get("stripe_session_id") in sids or (em and (r.get("email") or "").lower() == em)):
            return r
    return None


def create_checkout(stripe, base_url, report_id, key, email=None):
    """A hosted Stripe Checkout session for one unlock. Returns its URL. Raises on failure (caller shows a message)."""
    kwargs = {
        "mode": "payment",
        "line_items": [{"quantity": 1, "price_data": {
            "currency": CURRENCY, "unit_amount": PRICE_CENTS,
            "product_data": {"name": "Verilay fix prompts",
                             "description": f"Every fix prompt for one app, for {UNLOCK_DAYS} days, re-scans included.",
                             "tax_code": TAX_CODE}}}],
        "success_url": f"{base_url}/prompts/unlocked?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{base_url}/report/{report_id}?unlock=cancelled",
        "allow_promotion_codes": True,
        "metadata": {"product": PRODUCT, "report_id": report_id, "app_key": key},
        "payment_intent_data": {"metadata": {"product": PRODUCT, "report_id": report_id, "app_key": key}},
    }
    if email:
        kwargs["customer_email"] = email.strip().lower()
    return stripe.checkout.Session.create(**kwargs).url


def is_prompt_session(session):
    return ((session or {}).get("metadata") or {}).get("product") == PRODUCT


def record(sb, session, event_id=None, now=None):
    """Write the unlock once (a duplicate stripe_session_id is the normal, expected path: the webhook and the success
    page both call this). Returns the row, or None. Raises only on a real database failure, so the webhook can ask
    Stripe to retry."""
    if sb is None or not is_prompt_session(session) or session.get("payment_status") != "paid":
        return None
    meta = session.get("metadata") or {}
    details = session.get("customer_details") or {}
    pi = session.get("payment_intent")
    if isinstance(pi, dict):
        pi = pi.get("id")
    row = {
        "stripe_session_id": session.get("id"),
        "stripe_event_id": event_id,
        "stripe_payment_intent": pi,
        "report_id": str(meta.get("report_id") or "")[:40],
        "app_key": str(meta.get("app_key") or "")[:140],
        "email": (details.get("email") or session.get("customer_email") or "").strip().lower() or None,
        "amount_cents": session.get("amount_total"),
        "currency": (session.get("currency") or "").lower(),
        "status": "active",
        "expires_at": ((now or _now()) + timedelta(days=UNLOCK_DAYS)).isoformat(),
    }
    if not row["stripe_session_id"] or not row["report_id"] or not row["app_key"]:
        print(f"[prompts] refusing to record an unlock with missing fields: {row.get('stripe_session_id')}", flush=True)
        return None
    try:
        res = sb.table(TABLE).insert(row).execute()
        print(f"[prompts] unlock recorded: {row['app_key']} report {row['report_id']}", flush=True)
        return (res.data[0] if res.data else row)
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg or "23505" in msg:
            try:
                got = sb.table(TABLE).select("*").eq("stripe_session_id", row["stripe_session_id"]).limit(1).execute().data
                return got[0] if got else row
            except Exception:
                return row
        print(f"[prompts] unlock insert FAILED for {row['report_id']}: {e}", flush=True)
        raise


def revoke(sb, payment_intent, status):
    """A refunded or disputed unlock stops working."""
    if sb is None or not payment_intent:
        return
    try:
        sb.table(TABLE).update({"status": status}).eq("stripe_payment_intent", payment_intent).execute()
    except Exception as e:
        print(f"[prompts] could not mark {payment_intent} {status}: {e}", flush=True)


def unlocked_view(data):
    """The report with its full fixes back in place (after an unlock). A copy; the stored report is not changed here."""
    d = dict(data or {})
    if d.get("locked_fixes"):
        d["top_fixes"] = d["locked_fixes"]
    d.pop("locked_fixes", None)
    d["prompts_locked"] = False
    return d
