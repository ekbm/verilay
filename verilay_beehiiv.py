"""verilay_beehiiv.py - send newsletter sign-ups from verilay.dev to beehiiv (27 Oct 2026).

Moses chose beehiiv for the monthly newsletter and an automatic sync: the moment someone subscribes on verilay.dev,
they are added to the beehiiv publication too (beehiiv then sends its confirmation and welcome emails). Verilay keeps
its own copy in the waitlist table first, so nothing is lost when beehiiv is down or the key is wrong; the admin can
import those by hand.

Railway settings (Moses adds them himself; never in chat or code):
  BEEHIIV_API_KEY         an API key from beehiiv (Settings -> API)
  BEEHIIV_PUBLICATION_ID  the publication's ID, starting with "pub_"
Unset, nothing is sent and nothing changes.

The key is never logged or shown. Only the outcome (added / refused, with beehiiv's status code) is kept, in memory,
for the admin page.
"""
import os
import re
import threading
import time

import requests

API = "https://api.beehiiv.com/v2"
TIMEOUT = 10
_RECENT = []                 # (time, ok, detail) of the latest attempts, newest last; no emails kept here
_LOCK = threading.Lock()


def _key():
    return (os.getenv("BEEHIIV_API_KEY", "") or "").strip()


def _pub():
    p = (os.getenv("BEEHIIV_PUBLICATION_ID", "") or "").strip()
    return p if re.fullmatch(r"pub_[A-Za-z0-9-]{4,64}", p) else ""


def configured():
    return bool(_key() and _pub())


def _remember(ok, detail):
    with _LOCK:
        _RECENT.append((time.time(), bool(ok), str(detail)[:120]))
        del _RECENT[:-50]


def recent():
    """[(time, ok, detail)], newest first, for the admin page."""
    with _LOCK:
        return list(reversed(_RECENT))


def add_subscriber(email, place="page", post=None):
    """Add one email to the beehiiv publication. Returns (ok, detail). Never raises. beehiiv's own double opt-in
    setting applies (they confirm by email, then get the welcome email)."""
    if not configured():
        return False, "beehiiv is not set up (BEEHIIV_API_KEY / BEEHIIV_PUBLICATION_ID)"
    post = post or requests.post
    try:
        r = post(f"{API}/publications/{_pub()}/subscriptions",
                 headers={"Authorization": f"Bearer {_key()}", "Content-Type": "application/json"},
                 json={"email": email, "send_welcome_email": True, "double_opt_override": "not_set",
                       "reactivate_existing": False, "utm_source": "verilay.dev", "utm_medium": str(place)[:30],
                       "referring_site": "https://verilay.dev"},
                 timeout=TIMEOUT)
        code = getattr(r, "status_code", 0)
        if code in (200, 201):
            _remember(True, f"added ({code})")
            return True, f"added ({code})"
        why = {401: "the API key was refused", 404: "the publication ID was not found", 429: "beehiiv is rate limiting",
               400: "beehiiv refused the request"}.get(code, f"beehiiv answered {code}")
        _remember(False, why)
        print(f"[beehiiv] subscriber not added: {why}", flush=True)
        return False, why
    except Exception as e:
        _remember(False, f"could not reach beehiiv ({type(e).__name__})")
        print(f"[beehiiv] could not reach beehiiv: {type(e).__name__}", flush=True)
        return False, f"could not reach beehiiv ({type(e).__name__})"


def check(get=None):
    """For the health page: ('ok' | 'warn' | 'fail' | 'off', text). Reads the publication; sends nothing."""
    if not configured():
        return "off", "not set up (BEEHIIV_API_KEY and BEEHIIV_PUBLICATION_ID on Railway)"
    get = get or requests.get
    try:
        r = get(f"{API}/publications/{_pub()}", headers={"Authorization": f"Bearer {_key()}"}, timeout=TIMEOUT)
    except Exception as e:
        return "warn", f"could not reach beehiiv: {type(e).__name__}"
    code = getattr(r, "status_code", 0)
    if code == 200:
        return "ok", "key and publication accepted"
    if code == 401:
        return "fail", "the API key was refused: make a new one in beehiiv and update BEEHIIV_API_KEY"
    if code == 404:
        return "fail", "the publication ID was not found: check BEEHIIV_PUBLICATION_ID (starts with pub_)"
    return "warn", f"beehiiv answered {code}"
