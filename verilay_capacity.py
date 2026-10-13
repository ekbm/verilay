"""
verilay_capacity.py — how many scans may run at once (2026-10-13).

A free scan holds one of the server's request slots for its whole run (2 to 4 minutes), and every scan makes
paid AI calls. With no limit, a burst of scans slows every visitor down and runs up the AI bill. So each server
process allows a fixed number of free scans at once; beyond that the visitor gets a kind "busy, try again in a
minute" message and is NOT charged an hourly allowance hit for it. Deep scans are capped by the number of jobs
running (see verilay_deepscan.running_job_count); the admin is exempt from both.

Counted per server process (Railway runs 4), so the real total is 4 times the free-scan number. Changing the
numbers needs no deploy: set VERILAY_MAX_FREE_SCANS / VERILAY_MAX_DEEP_SCANS on Railway.
"""
import os
import threading
import time
import uuid


class Slots:
    """A leak-proof counter of scans running right now in this process.

    A slot held longer than max_age_seconds is treated as free again (the longest real scan is about 7 minutes),
    so a scan that dies without releasing can never block the server for good."""

    def __init__(self, limit, max_age_seconds=900):
        self.limit = max(1, int(limit))
        self.max_age = max_age_seconds
        self._held = {}
        self._lock = threading.Lock()

    def _purge(self, now):
        for tok, t in list(self._held.items()):
            if now - t > self.max_age:
                del self._held[tok]

    def try_acquire(self):
        """A token when a slot was free, otherwise None. Never blocks."""
        with self._lock:
            now = time.time()
            self._purge(now)
            if len(self._held) >= self.limit:
                return None
            tok = uuid.uuid4().hex
            self._held[tok] = now
            return tok

    def release(self, token):
        with self._lock:
            self._held.pop(token, None)

    def active(self):
        with self._lock:
            self._purge(time.time())
            return len(self._held)


def _env_int(name, default):
    try:
        v = int(os.getenv(name, "") or default)
        return v if v >= 1 else default
    except ValueError:
        return default


FREE_SCANS = Slots(_env_int("VERILAY_MAX_FREE_SCANS", 8))
DEEP_SCAN_LIMIT = _env_int("VERILAY_MAX_DEEP_SCANS", 3)

BUSY_MESSAGE = ("Verilay is running a lot of analyses right now. Please try again in a minute or two. "
                "This attempt did not use any of your hourly allowance.")
DEEP_BUSY_MESSAGE = ("Several deep scans are running right now. Please try again in a few minutes. "
                     "Nothing was started and your scan has not been used.")
