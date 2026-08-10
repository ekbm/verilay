#!/usr/bin/env python3
"""
Verilay — accounts, for paid users only.

The free tool stays exactly as it was: no account, no login, nothing to sign up
for. An account exists for one reason — someone paid, and their reports should
still be there next week when they come back to check whether their fixes worked.

Sign-in is by email with no password. Supabase Auth sends the email; we never
store or compare a credential, so there is nothing here worth stealing. Two ways
in, both from the same email:

  • a link  — clicked, handled by /auth/callback
  • a code  — six digits, typed into the form, handled by /auth/code

The code path is the one to rely on. It is entirely server-side, so it works with
Flask's plain server-rendered pages. The link path needs a few lines of
JavaScript because Supabase returns the token in the URL *fragment*, which the
browser never sends to a server.

IMPORTANT — SECRET_KEY. Sessions here are signed with app.secret_key. Verilay
previously fell back to a random key per process, which was harmless when nothing
used sessions. It is not harmless now: Gunicorn runs several workers, each would
invent a different key, and a signed-in user would be randomly logged out
whenever a request landed on a different worker. SECRET_KEY must be set in the
environment and must not change.

© 2026 Moses Ekbote.
"""

import os
import re
import time
import threading
from functools import wraps

from flask import session, redirect, request

try:
    from supabase import create_client as _create_client
    _HAS_SUPABASE_LIB = True
except Exception:
    _create_client = None
    _HAS_SUPABASE_LIB = False


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
# Auth calls should use the anon (publishable) key. It is the right key for
# "sign this person in" and it is what Supabase's own examples use. If only the
# one existing key is set we fall back to it so nothing breaks, but see
# PAYWALL_SETUP.md — set SUPABASE_ANON_KEY.
SUPABASE_ANON_KEY = (os.getenv("SUPABASE_ANON_KEY", "").strip()
                     or os.getenv("SUPABASE_KEY", "").strip())

SESSION_DAYS = 30
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def configured():
    return bool(_HAS_SUPABASE_LIB and SUPABASE_URL and SUPABASE_ANON_KEY)


def _auth_client():
    """A FRESH client for every auth call — deliberately not the shared one.

    supabase-py stores the signed-in session on the client object. The app has one
    long-lived client shared by 16 threads, so calling verify_otp on it would make
    that client "be" whoever signed in most recently, and unrelated database
    queries on other threads would run as that user. A throwaway client per call
    keeps a sign-in from leaking sideways.
    """
    if not configured():
        raise RuntimeError("Supabase auth is not configured")
    return _create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# ── Sending codes ──────────────────────────────────────────────────────────────
# A login form that emails anyone on request is a way to burn through an email
# quota and to use verilay.dev as a way to send mail to strangers. Two limits:
# per address, and per caller.
_send_lock = threading.Lock()
_sent_by_email = {}
_sent_by_ip = {}

MAX_PER_EMAIL_HOUR = 5
MAX_PER_IP_HOUR = 12


def _allow_send(email, ip):
    now = time.time()
    with _send_lock:
        for store, key, cap in ((_sent_by_email, email, MAX_PER_EMAIL_HOUR),
                                (_sent_by_ip, ip or "unknown", MAX_PER_IP_HOUR)):
            hits = [t for t in store.get(key, []) if now - t < 3600]
            if len(hits) >= cap:
                store[key] = hits
                return False
            hits.append(now)
            store[key] = hits
        # Same unbounded-growth problem the analysis rate limiter had.
        if len(_sent_by_email) > 5000:
            for k in [k for k, v in list(_sent_by_email.items()) if not v]:
                _sent_by_email.pop(k, None)
        if len(_sent_by_ip) > 5000:
            for k in [k for k, v in list(_sent_by_ip.items()) if not v]:
                _sent_by_ip.pop(k, None)
    return True


def valid_email(value):
    return bool(value and EMAIL_RE.match(value.strip().lower()) and len(value) <= 254)


def send_login_email(email, ip=None, base_url="https://verilay.dev", create_user=True):
    """Email a sign-in link and code. Returns (ok, message).

    `create_user=False` is used nowhere yet, but is the switch to flip if you ever
    want sign-in restricted to people who have already bought something.
    """
    email = (email or "").strip().lower()
    if not valid_email(email):
        return False, "That does not look like an email address."
    if not configured():
        return False, "Sign-in is not available on this server yet."
    if not _allow_send(email, ip):
        return False, ("We have sent several sign-in emails to that address "
                       "already. Check your inbox and spam folder, or try again "
                       "in an hour.")
    try:
        _auth_client().auth.sign_in_with_otp({
            "email": email,
            "options": {
                "should_create_user": bool(create_user),
                "email_redirect_to": f"{base_url.rstrip('/')}/auth/callback",
            },
        })
    except Exception as e:
        print(f"[accounts] sign_in_with_otp failed for {email}: {e}", flush=True)
        return False, ("We could not send that email just now. Please try again, "
                       "or email moses@verilay.dev and I will sort it out.")
    print(f"[accounts] Sign-in email sent to {email}", flush=True)
    return True, "Check your email — we have sent you a sign-in link and a code."


# ── Verifying ──────────────────────────────────────────────────────────────────
def verify_code(email, code):
    """Exchange a six-digit code for a user. Returns (user_dict, error_message)."""
    email = (email or "").strip().lower()
    code = re.sub(r"\D", "", code or "")
    if not valid_email(email):
        return None, "That does not look like an email address."
    if len(code) < 6:
        return None, "That code should be six digits."
    try:
        res = _auth_client().auth.verify_otp({
            "email": email, "token": code, "type": "email",
        })
    except Exception as e:
        print(f"[accounts] verify_otp failed for {email}: {e}", flush=True)
        return None, "That code is wrong or has expired. Request a new one."
    user = getattr(res, "user", None)
    if not user:
        return None, "That code is wrong or has expired. Request a new one."
    return {"id": str(user.id), "email": (user.email or email).lower()}, None


def verify_access_token(access_token):
    """Confirm an access token from the magic-link fragment. Returns (user, error)."""
    if not access_token or len(access_token) > 4096:
        return None, "Missing sign-in token."
    try:
        res = _auth_client().auth.get_user(access_token)
    except Exception as e:
        print(f"[accounts] get_user failed: {e}", flush=True)
        return None, "That sign-in link has expired. Request a new one."
    user = getattr(res, "user", None)
    if not user or not user.email:
        return None, "That sign-in link has expired. Request a new one."
    return {"id": str(user.id), "email": user.email.lower()}, None


# ── Our own session ────────────────────────────────────────────────────────────
# Supabase's access token is not kept. Once we know who they are, a signed Flask
# cookie holding an id and an email is all any page here needs, and it means a
# leaked cookie cannot be replayed against the Supabase API.
def log_in(user):
    session.permanent = True
    session["uid"] = user["id"]
    session["email"] = user["email"]
    session["since"] = int(time.time())


def log_out():
    for k in ("uid", "email", "since"):
        session.pop(k, None)


def current_user():
    uid = session.get("uid")
    email = session.get("email")
    if not uid or not email:
        return None
    return {"id": uid, "email": email}


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not current_user():
            nxt = request.full_path if request.method == "GET" else "/account"
            return redirect(f"/login?next={nxt}")
        return view(*a, **kw)
    return wrapped
