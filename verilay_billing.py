#!/usr/bin/env python3
"""
Verilay — billing.

One product: a deep scan of one app, plus re-scans of that same app for 30 days.
$19 AUD, one-off. No subscriptions, no cards touched by us — Stripe Checkout is
hosted on Stripe's own domain, so this file never sees a card number.

Two rules worth keeping in mind if you change anything here:

1. The WEBHOOK is the source of truth for "they paid", not the success redirect.
   A redirect is just the browser being told to go somewhere; anyone can visit
   /checkout/success with a made-up id. The webhook is signed by Stripe with a
   secret only Stripe and this server know.

2. Every purchase is written once and only once. Stripe deliberately retries
   webhooks (it cannot tell a lost reply from a failed one), so the same payment
   WILL arrive more than once. `stripe_event_id` is a unique column, and a
   duplicate insert failing is the normal, expected path — not an error.

© 2026 Moses Ekbote.
"""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

try:
    import stripe as _stripe
    _HAS_STRIPE = True
except ImportError:          # so the free app still boots if the dep is missing
    _stripe = None
    _HAS_STRIPE = False


# ── Configuration ──────────────────────────────────────────────────────────────
# PAYWALL_ENABLED is the master switch. While it is off, /deep-scan shows the
# waitlist instead of a Buy button and /checkout refuses to create a session, so
# there is no way to be charged for something that cannot yet be delivered.
def _flag(name, default="0"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


PAYWALL_ENABLED      = _flag("PAYWALL_ENABLED")
STRIPE_SECRET_KEY    = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
STRIPE_PRICE_ID      = os.getenv("STRIPE_PRICE_ID", "").strip()
# .strip() before .rstrip("/") — pasting a variable into a dashboard field very
# easily carries a leading space, and " https://verilay.dev/checkout/success" is
# not a URL Stripe will accept. Whitespace in an environment variable should never
# be the reason checkout fails.
BASE_URL             = os.getenv("BASE_URL", "https://verilay.dev").strip().rstrip("/")

# Used only when STRIPE_PRICE_ID is not set, so test mode works before you have
# created the product in the dashboard.
PRICE_CENTS = int(os.getenv("DEEP_SCAN_PRICE_CENTS", "1900").strip() or "1900")
PRICE_CURRENCY = os.getenv("DEEP_SCAN_CURRENCY", "aud").strip().lower() or "aud"

# Stripe tax classification for the deep scan. Required, not optional: this
# account has Managed Payments enabled (Stripe acts as merchant of record and
# handles tax), and Managed Payments refuses any line item without an eligible
# product tax code. Without it, checkout fails with "the product tax code is
# missing" and nobody can buy anything.
#
# txcd_10103001 = "Software as a service (SaaS) - business use": software
# delivered over the internet, not customised for the individual buyer, nothing
# downloaded. That is what a deep scan is. The business/personal distinction only
# affects US sales; business use is the right call for a paid pre-launch review of
# an app someone is about to ship.
DEEP_SCAN_TAX_CODE = os.getenv("DEEP_SCAN_TAX_CODE", "txcd_10103001").strip() or "txcd_10103001"

ENTITLEMENT_DAYS = 30

# A quiet internal ceiling on re-scans, to bound the cost of a single purchase if
# someone automates it. A deep scan costs 15–40c, so 15 re-scans is ~$2–6 against
# $19. NEVER show this number in the UI: "re-scan whenever you like" reads
# generously, "up to 15 re-scans" makes people count.
MAX_SCANS_PER_PURCHASE = 15

if _HAS_STRIPE and STRIPE_SECRET_KEY:
    _stripe.api_key = STRIPE_SECRET_KEY


def is_live_key():
    """True if we are pointed at real money. Used to warn in the startup log."""
    return STRIPE_SECRET_KEY.startswith(("sk_live_", "rk_live_"))


def account_hint():
    """Which Stripe account this key belongs to, derived from the key itself.

    Stripe embeds the account id in the key: a key body of '51U2khdA0rN41rcGa…'
    means 'acct_1U2khdA0rN41rcGa'. Nothing secret is revealed — an account id is
    not a credential — and it answers the one question that is otherwise invisible
    from outside: whether the key, the price and the webhook all live in the SAME
    account. They must. Stripe objects never cross accounts, and a key from a
    sandbox looking at another account's price fails with a bare
    "No such price", which reads like a typo rather than the real cause.

    A hint, not a promise: it is inferred from the key's shape, so treat a
    mismatch as a prompt to check the dashboard, not as proof.
    """
    parts = STRIPE_SECRET_KEY.split("_")
    if len(parts) < 3:
        return None
    body = parts[2]
    if not body.startswith("5") or len(body) < 17:
        return None
    return "acct_" + body[1:17]


def configured():
    """Everything needed to actually sell is present."""
    return bool(_HAS_STRIPE and STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET)


# ── Identifying "the same app" ─────────────────────────────────────────────────
_REPO_PART = re.compile(r"[A-Za-z0-9._-]{1,100}")


def normalise_repo(value):
    """Reduce anything the user might paste to a canonical `owner/repo`.

    A purchase is tied to one app, so this string is the thing being bought. All
    of these have to land on the same value, or a buyer re-scanning the same repo
    would be asked to pay twice:

        https://github.com/Ekbm/Verilay
        github.com/ekbm/verilay.git
        ekbm/verilay/
        HTTPS://GitHub.com/ekbm/verilay/tree/main/src

    Lowercased because GitHub owner and repo names are case-insensitive.
    Returns None if it cannot be read as a repo, and callers must treat None as
    "refuse", never as "allow".
    """
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    v = re.sub(r"^https?://", "", v, flags=re.I)
    v = re.sub(r"^www\.", "", v, flags=re.I)
    v = re.sub(r"^github\.com/", "", v, flags=re.I)
    v = v.strip("/")
    if not v:
        return None
    parts = [p for p in v.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not _REPO_PART.fullmatch(owner) or not _REPO_PART.fullmatch(repo):
        return None
    # '.' and '..' match the pattern above but are path segments, not names, so
    # 'github.com/../../etc/passwd' would otherwise normalise to '../..' and get
    # stored as a repo and put back into URLs. A real repo can be called
    # '.github', but it can never be '.' or '..'.
    if owner.strip(".") == "" or repo.strip(".") == "":
        return None
    return f"{owner.lower()}/{repo.lower()}"


# ── Checkout ───────────────────────────────────────────────────────────────────
class BillingError(Exception):
    pass


def create_checkout_session(repo, email=None, client_ip=None):
    """Create a hosted Stripe Checkout session and return its URL.

    `repo` is carried in the session metadata rather than in a table of our own:
    Stripe hands it back to us on both the webhook and the success redirect, so
    there is nothing to expire or clean up, and no row to leak if someone
    abandons checkout.
    """
    if not PAYWALL_ENABLED:
        raise BillingError("The deep scan is not on sale yet.")
    if not configured():
        raise BillingError("Payments are not configured on this server.")

    canonical = normalise_repo(repo)
    if not canonical:
        raise BillingError(
            "That does not look like a GitHub repository. A deep scan is tied to "
            "one repo, so we need its address — for example github.com/you/your-app."
        )

    if STRIPE_PRICE_ID:
        line_items = [{"price": STRIPE_PRICE_ID, "quantity": 1}]
    else:
        line_items = [{
            "quantity": 1,
            "price_data": {
                "currency": PRICE_CURRENCY,
                "unit_amount": PRICE_CENTS,
                "product_data": {
                    "name": "Verilay Deep Scan",
                    "description": (
                        f"A deep scan of {canonical}, and re-scans whenever you "
                        f"like for {ENTITLEMENT_DAYS} days."
                    ),
                    "tax_code": DEEP_SCAN_TAX_CODE,
                },
            },
        }]

    kwargs = {
        "mode": "payment",
        "line_items": line_items,
        "success_url": f"{BASE_URL}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{BASE_URL}/deep-scan?cancelled=1",
        "allow_promotion_codes": True,
        # The email is how the buyer's account is created after payment, so it is
        # required rather than optional.
        "customer_creation": "always",
        "metadata": {"repo": canonical, "product": "deep_scan_v1"},
        # Also on the PaymentIntent, so a refund seen in the dashboard still says
        # which app it was for.
        "payment_intent_data": {"metadata": {"repo": canonical, "product": "deep_scan_v1"}},
    }
    if email:
        kwargs["customer_email"] = email.strip().lower()

    try:
        session = _stripe.checkout.Session.create(**kwargs)
    except Exception as e:
        # Never surface Stripe's raw message — it can name internal ids.
        print(f"[billing] Checkout create failed for {canonical}: {e}", flush=True)
        raise BillingError("Could not start checkout. Please try again in a moment.")

    print(f"[billing] Checkout started: {canonical} session={session.id}", flush=True)
    return session.url


def retrieve_paid_session(session_id):
    """Fetch a Checkout Session and return it only if it is genuinely paid.

    This is what lets the success page sign the buyer in immediately instead of
    waiting for the webhook — but it asks Stripe rather than trusting the URL, so
    a guessed or edited session_id gets nothing.
    """
    if not configured() or not session_id:
        return None
    try:
        s = _stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        print(f"[billing] Session retrieve failed: {e}", flush=True)
        return None
    if s.get("payment_status") != "paid":
        return None
    return s


class BadSignature(BillingError):
    """The request was not signed by Stripe. Answer 400 and do not retry."""


def verify_webhook(payload, sig_header):
    """Verify Stripe's signature and return the event.

    Without this check the webhook endpoint would be a public "give me a free
    deep scan" URL, because anyone can POST JSON to it.

    Two failure modes, deliberately different exceptions, because they need
    opposite answers. A bad signature is someone else's problem and must get a
    400 so Stripe stops. Anything else — a payload shape this SDK version cannot
    build, a library change — is OUR problem, and must get a 500 so Stripe keeps
    retrying and the event stays visible as failed in the dashboard instead of
    being silently accepted and dropped.
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise BadSignature("Webhook secret not configured")
    if not _HAS_STRIPE:
        raise BillingError("Stripe library not installed")
    # Must be decoded to str first. verify_header builds the signed payload with
    # "%d.%s" % (timestamp, payload), so passing raw bytes would hash the literal
    # text "b'{...}'" and never match a genuine Stripe signature.
    text = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload
    try:
        _stripe.WebhookSignature.verify_header(
            text, sig_header, STRIPE_WEBHOOK_SECRET, tolerance=300
        )
    except Exception as e:
        raise BadSignature(f"Signature verification failed: {e}")
    try:
        return json.loads(text)
    except Exception as e:
        raise BillingError(f"Signed payload was not readable JSON: {e}")


# ── Purchases ──────────────────────────────────────────────────────────────────
def _session_fields(session):
    """Pull the handful of values we store out of a Checkout Session object."""
    details = session.get("customer_details") or {}
    email = (details.get("email") or session.get("customer_email") or "").strip().lower()
    meta = session.get("metadata") or {}
    pi = session.get("payment_intent")
    if isinstance(pi, dict):
        pi = pi.get("id")
    return {
        "email": email,
        "repo": normalise_repo(meta.get("repo", "")),
        "session_id": session.get("id"),
        "payment_intent": pi,
        "amount_cents": session.get("amount_total"),
        "currency": (session.get("currency") or "").lower(),
    }


def record_purchase(sb, session, event_id):
    """Write the purchase once. Returns (purchase_row_or_None, created_bool).

    A duplicate `stripe_event_id` is not a failure — it means Stripe retried a
    delivery we already handled, which is normal and must stay silent.
    """
    if sb is None:
        print("[billing] No Supabase — purchase NOT recorded. This is data loss.", flush=True)
        return None, False

    f = _session_fields(session)
    if not f["email"] or not f["repo"]:
        print(f"[billing] Refusing to record purchase with missing email/repo: {f}", flush=True)
        return None, False

    expires = datetime.now(timezone.utc) + timedelta(days=ENTITLEMENT_DAYS)
    row = {
        "stripe_event_id": event_id,
        "stripe_session_id": f["session_id"],
        "stripe_payment_intent": f["payment_intent"],
        "email": f["email"],
        "repo": f["repo"],
        "amount_cents": f["amount_cents"],
        "currency": f["currency"],
        "expires_at": expires.isoformat(),
        "status": "active",
    }
    try:
        res = sb.table("purchases").insert(row).execute()
        print(f"[billing] Purchase recorded: {f['email']} → {f['repo']}", flush=True)
        return (res.data[0] if res.data else row), True
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg or "23505" in msg:
            print(f"[billing] Duplicate webhook for event {event_id} — already recorded.", flush=True)
            return None, False
        print(f"[billing] Purchase insert FAILED for {f['email']} / {f['repo']}: {e}", flush=True)
        raise


def link_purchases_to_user(sb, email, user_id):
    """Attach any purchases bought with this email to the account.

    Purchases are recorded against the Stripe email before the account exists, so
    this runs on every sign-in — it is cheap and means a buyer who later signs in
    with the same address finds their purchase waiting.
    """
    if sb is None or not email or not user_id:
        return 0
    try:
        res = (sb.table("purchases")
                 .update({"user_id": user_id})
                 .eq("email", email.strip().lower())
                 .is_("user_id", "null")
                 .execute())
        n = len(res.data or [])
        if n:
            print(f"[billing] Linked {n} purchase(s) to {email}", flush=True)
        return n
    except Exception as e:
        print(f"[billing] Could not link purchases for {email}: {e}", flush=True)
        return 0


def _is_active(row):
    if (row.get("status") or "") != "active":
        return False
    exp = row.get("expires_at")
    if not exp:
        return False
    try:
        # Supabase returns ISO 8601; tolerate a trailing Z.
        dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt < datetime.now(timezone.utc):
        return False
    return (row.get("scans_used") or 0) < MAX_SCANS_PER_PURCHASE


def active_purchase_for(sb, email, repo):
    """The buyer's live entitlement for this app, or None.

    Matched on email rather than user_id so the entitlement works on the success
    page, in the moment between paying and the account existing.
    """
    canonical = normalise_repo(repo)
    if sb is None or not email or not canonical:
        return None
    try:
        res = (sb.table("purchases")
                 .select("*")
                 .eq("email", email.strip().lower())
                 .eq("repo", canonical)
                 .order("created_at", desc=True)
                 .limit(5)
                 .execute())
    except Exception as e:
        # Loud, because the most likely cause is SUPABASE_KEY not being allowed to
        # read this table — which would silently deny every paying customer.
        print(f"[billing] Entitlement lookup FAILED for {email}/{canonical}: {e}", flush=True)
        return None
    for row in (res.data or []):
        if _is_active(row):
            return row
    return None


def purchases_for_email(sb, email):
    """Everything this address has ever bought, newest first."""
    if sb is None or not email:
        return []
    try:
        res = (sb.table("purchases")
                 .select("*")
                 .eq("email", email.strip().lower())
                 .order("created_at", desc=True)
                 .limit(50)
                 .execute())
        rows = res.data or []
    except Exception as e:
        print(f"[billing] purchases_for_email failed for {email}: {e}", flush=True)
        return []
    for r in rows:
        r["_active"] = _is_active(r)
    return rows


def consume_scan(sb, purchase_id):
    """Count a deep scan against a purchase. Best effort — never blocks a scan.

    Read-then-write is not atomic across Gunicorn workers, so a buyer running two
    scans in the same instant could have one go uncounted. That is the right
    trade-off here: the counter exists to bound abuse, and undercounting by one
    costs cents, while refusing a scan a customer paid for costs trust.
    """
    if sb is None or not purchase_id:
        return
    try:
        cur = sb.table("purchases").select("scans_used").eq("id", purchase_id).execute()
        used = (cur.data[0].get("scans_used") or 0) if cur.data else 0
        sb.table("purchases").update({"scans_used": used + 1}).eq("id", purchase_id).execute()
    except Exception as e:
        print(f"[billing] Could not increment scans_used on {purchase_id}: {e}", flush=True)


def price_label():
    """Human price for the UI, e.g. '$19 AUD'."""
    whole = PRICE_CENTS // 100
    cents = PRICE_CENTS % 100
    amount = f"${whole}" if cents == 0 else f"${whole}.{cents:02d}"
    return f"{amount} {PRICE_CURRENCY.upper()}"
