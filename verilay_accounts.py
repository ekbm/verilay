#!/usr/bin/env python3
"""
Verilay — accounts, for paid users only.

The free tool stays exactly as it was: no account, no login, nothing to sign up
for. An account exists for one reason — someone paid, and their reports should
still be there next week when they come back to check whether their fixes worked.

Sign-in is by email with no password. Supabase Auth sends the email; we never
store or compare a credential, so there is nothing here worth stealing. Since
21 Oct 2026 the email carries a LINK only (Moses's decision; the email template no
longer has a code):

  • a link  — clicked, handled by /auth/callback. It needs a few lines of
    JavaScript, because Supabase returns the token in the URL *fragment*, which
    the browser never sends to a server.
  • the older six-digit code path, /auth/code, still exists and still works, but
    no page links to it and the email no longer contains a code.

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
# A sign-in email can take a minute to arrive (26 Oct 2026: Moses got "could not send", retried, and then three emails
# arrived at once, each cancelling the one before). Within this many seconds of the last request for the same address,
# no new email is asked for: the visitor is told to check their inbox and wait.
RESEND_WAIT_SECONDS = 60


def seconds_since_last_send(email):
    with _send_lock:
        hits = _sent_by_email.get(email) or []
    return (time.time() - hits[-1]) if hits else None


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
    """Email a sign-in link. Returns (ok, message).

    `create_user=False` is used nowhere yet, but is the switch to flip if you ever
    want sign-in restricted to people who have already bought something.
    """
    email = (email or "").strip().lower()
    if not valid_email(email):
        return False, "That does not look like an email address."
    if not configured():
        return False, "Sign-in is not available on this server yet."
    since = seconds_since_last_send(email)
    if since is not None and since < RESEND_WAIT_SECONDS:
        wait = max(5, int(RESEND_WAIT_SECONDS - since))
        return False, (f"We already sent a sign-in link to that address just now. It can take a minute or two to arrive, so please "
                       f"check your inbox and spam folder first. You can ask for another in about {wait} seconds.")
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
        msg = str(e).lower()
        if "rate limit" in msg or ("after" in msg and "second" in msg):
            return False, ("Lots of sign-in emails are going out right now. Please wait a minute, check your inbox and spam "
                           "folder, and only then ask for another link.")
        # Often the email is on its way and only the answer was slow: say so, so people wait instead of asking again
        # (each new link cancels the one before).
        return False, ("Sending is taking longer than usual. The email may still arrive: please check your inbox and spam folder "
                       "in a minute or two before trying again. Nothing after 5 minutes? Try again, or email moses@verilay.dev.")
    print(f"[accounts] Sign-in email sent to {email}", flush=True)
    return True, "Check your email — we have sent you a sign-in link."


# ── "Email me this report" ──────────────────────────────────────────────────────
def _save_link(email, base_url):
    """A one-click sign-in link made by Supabase but sent in Verilay's own email, so that email can carry the report.
    "magiclink" is for an existing account, "invite" creates one. None when neither works (then the caller falls back
    to the normal sign-in email). Needs the server's own database key (SUPABASE_KEY)."""
    key = os.getenv("SUPABASE_KEY", "").strip()
    if not (_HAS_SUPABASE_LIB and SUPABASE_URL and key):
        return None
    redirect_to = f"{base_url.rstrip('/')}/auth/callback"
    for kind in ("magiclink", "invite"):
        try:
            res = _create_client(SUPABASE_URL, key).auth.admin.generate_link(
                {"type": kind, "email": email, "options": {"redirect_to": redirect_to}})
            link = getattr(getattr(res, "properties", None), "action_link", "") or ""
            if link.startswith("https://"):
                return link
        except Exception as e:
            print(f"[accounts] generate_link ({kind}) failed for {email}: {e}", flush=True)
    return None


def send_report_email(email, ip, base_url, report_url, repo, headline, want_save=True):
    """Email a report link; with `want_save`, also a link that signs them in and saves the report to their account.
    Shares the sign-in email limits, so it cannot be used to send mail to strangers. Returns (ok, message)."""
    import verilay_notify as notify
    email = (email or "").strip().lower()
    if not valid_email(email):
        return False, "That does not look like an email address."
    since = seconds_since_last_send(email)
    if since is not None and since < RESEND_WAIT_SECONDS:
        wait = max(5, int(RESEND_WAIT_SECONDS - since))
        return False, (f"We already sent an email to that address just now. It can take a minute or two to arrive, so please "
                       f"check your inbox and spam folder first. You can ask again in about {wait} seconds.")
    if not _allow_send(email, ip):
        return False, "We have sent several emails to that address already. Check your inbox and spam folder, or try again in an hour."
    link = _save_link(email, base_url) if (want_save and notify.configured()) else None
    separate = False
    if want_save and not link:
        # Fall back to Supabase's normal sign-in email: signing in with it still saves the report.
        if not configured():
            return False, "Saving reports by email is not available right now. Please try again later."
        try:
            _auth_client().auth.sign_in_with_otp({"email": email, "options": {
                "should_create_user": True, "email_redirect_to": f"{base_url.rstrip('/')}/auth/callback"}})
            separate = True
        except Exception as e:
            print(f"[accounts] report save sign-in email failed for {email}: {e}", flush=True)
            return False, "Sending is taking longer than usual. Please wait a minute, check your inbox, then try again."
    sent = notify.send_report_email(email, repo, headline, report_url, save_link=link, separate_save=separate)
    if not sent and not separate:
        return False, "We could not send the email just now. Please try again in a minute."
    if not want_save:
        return True, f"We emailed a copy of this report to {email}."
    if separate and not sent:
        return True, f"We sent a sign-in link to {email}. Click it to save this report to your account."
    if separate:
        return True, (f"We sent the report link to {email}, and a separate sign-in link: click that one to save it. "
                      "It can take a minute or two, so check spam too.")
    return True, (f"We sent the report link to {email}. Click \u201cSave my report\u201d in the email to keep it. "
                  "It can take a minute or two, so check spam too.")


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
