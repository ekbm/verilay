"""verilay_usage.py - how much AI a scan really uses, so "free with limits" can be priced from facts (2026-10-20).

Counts only. It never stores a prompt, an answer, a line of code, a repository name, an email or an address. For each day it keeps a
handful of numbers in the existing `stats` table (key = "usage:<date>:<name>", value = a whole number):

  scan_calls / scan_input_tokens / scan_output_tokens   AI calls for scans (this also includes the Part 2 fix prompts and any deep scan that day)
  ask_calls  / ask_input_tokens  / ask_output_tokens    the Ask Verilay question box
  scans_full / scans_replayed / scans_preview           finished scans: analysed in full, replayed from a saved result (no AI), live-address preview

The numbers are approximate on purpose: two workers can update the same number at the same moment and one update can be lost, and a
restart can lose the last few seconds. That is fine for working out an average. Nothing here can slow down or break a scan: every call is
best effort and swallows its own errors.

To turn tokens into money, set AI_PRICE_INPUT_PER_MTOK and AI_PRICE_OUTPUT_PER_MTOK on Railway (US dollars per million tokens, from the
price list for the model in use). With no prices set, only tokens are shown: no price is guessed here.
"""
import os
import threading
import time
from datetime import datetime, timedelta

KINDS = ("scan", "ask")
SCAN_KINDS = ("full", "replayed", "preview")
FLUSH_EVERY_SECONDS = 60
MAX_PENDING_KEYS = 200

_lock = threading.Lock()
_pending = {}
_last_flush = 0.0
_get_sb = lambda: None


def init(get_sb):
    """Tell the module how to reach the database (a function that returns the client, or None)."""
    global _get_sb
    _get_sb = get_sb


def _today(now=None):
    return (now or datetime.utcnow()).strftime("%Y-%m-%d")


def _bump(name, amount, now=None):
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return
    key = f"usage:{_today(now)}:{name}"
    with _lock:
        _pending[key] = _pending.get(key, 0) + amount
        if len(_pending) > MAX_PENDING_KEYS:      # a database that never answers must not grow memory without end
            _pending.clear()


def record(input_tokens=None, output_tokens=None, kind="scan", now=None):
    """One AI call. Token counts may be unknown (None); the call is still counted. Never raises."""
    try:
        if kind not in KINDS:
            return
        _bump(f"{kind}_calls", 1, now)
        if isinstance(input_tokens, int):
            _bump(f"{kind}_input_tokens", input_tokens, now)
        if isinstance(output_tokens, int):
            _bump(f"{kind}_output_tokens", output_tokens, now)
        _maybe_flush()
    except Exception:
        pass


def record_from_stream(stream, kind="scan"):
    """Read the token counts from a finished Anthropic streaming call. Counts only; never touches the text. Never raises."""
    try:
        usage = stream.get_final_message().usage
        record(getattr(usage, "input_tokens", None), getattr(usage, "output_tokens", None), kind)
    except Exception:
        record(None, None, kind)


def scan_done(kind, now=None):
    """A scan finished: 'full', 'replayed' or 'preview'. Flushes, so a quiet site still gets its numbers saved."""
    try:
        if kind in SCAN_KINDS:
            _bump(f"scans_{kind}", 1, now)
        flush()
    except Exception:
        pass


def _maybe_flush():
    if time.time() - _last_flush >= FLUSH_EVERY_SECONDS:
        flush()


def flush():
    """Write the pending numbers to the database. Best effort: on any error the numbers stay pending for the next try."""
    global _last_flush
    _last_flush = time.time()
    try:
        sb = _get_sb()
        if sb is None:
            return False
        with _lock:
            todo = dict(_pending)
        if not todo:
            return True
        for key, delta in todo.items():
            res = sb.table("stats").select("value").eq("key", key).execute()
            if res.data:
                sb.table("stats").update({"value": int(res.data[0]["value"] or 0) + delta}).eq("key", key).execute()
            else:
                sb.table("stats").insert({"key": key, "value": delta}).execute()
            with _lock:                         # only what was written is removed; anything added meanwhile stays
                left = _pending.get(key, 0) - delta
                if left > 0:
                    _pending[key] = left
                else:
                    _pending.pop(key, None)
        return True
    except Exception:
        return False


def _prices():
    try:
        pin = float(os.getenv("AI_PRICE_INPUT_PER_MTOK", "").strip())
        pout = float(os.getenv("AI_PRICE_OUTPUT_PER_MTOK", "").strip())
        return (pin, pout) if pin >= 0 and pout >= 0 else None
    except Exception:
        return None


def summary(days=14, now=None):
    """Per-day numbers for the last `days` days, newest first, plus averages. Plain data; never raises."""
    try:
        sb = _get_sb()
        if sb is None:
            return {"available": False, "reason": "no database"}
        flush()
        rows = sb.table("stats").select("key,value").like("key", "usage:%").execute().data or []
        cutoff = _today((now or datetime.utcnow()) - timedelta(days=max(1, int(days)) - 1))
        by_day = {}
        for r in rows:
            parts = str(r.get("key", "")).split(":", 2)
            if len(parts) == 3 and parts[1] >= cutoff:
                by_day.setdefault(parts[1], {})[parts[2]] = int(r.get("value") or 0)
        prices = _prices()
        out_days, tot = [], {}
        for day in sorted(by_day, reverse=True):
            d = dict(by_day[day])
            if prices:
                d["est_cost_usd"] = round((d.get("scan_input_tokens", 0) + d.get("ask_input_tokens", 0)) * prices[0] / 1e6
                                          + (d.get("scan_output_tokens", 0) + d.get("ask_output_tokens", 0)) * prices[1] / 1e6, 4)
            out_days.append({"date": day, **d})
            for k, v in d.items():
                tot[k] = tot.get(k, 0) + v
        full = tot.get("scans_full", 0)
        avg = {}
        if full:
            avg["scan_tokens_per_full_scan"] = round((tot.get("scan_input_tokens", 0) + tot.get("scan_output_tokens", 0)) / full)
            avg["scan_calls_per_full_scan"] = round(tot.get("scan_calls", 0) / full, 1)
            if prices:
                avg["est_cost_usd_per_full_scan"] = round(((tot.get("scan_input_tokens", 0)) * prices[0] / 1e6
                                                           + (tot.get("scan_output_tokens", 0)) * prices[1] / 1e6) / full, 4)
        return {"available": True, "days": out_days, "totals": tot, "averages": avg, "prices_set": bool(prices),
                "note": ("Approximate. Scan figures include the Part 2 fix prompts and any deep scan that day; replayed scans use no AI. "
                         "Cost needs AI_PRICE_INPUT_PER_MTOK and AI_PRICE_OUTPUT_PER_MTOK to be set." if not prices else
                         "Approximate. Scan figures include the Part 2 fix prompts and any deep scan that day; replayed scans use no AI.")}
    except Exception as e:
        return {"available": False, "reason": type(e).__name__}
