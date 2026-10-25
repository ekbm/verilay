"""verilay_usage.py - how much AI a scan really uses, so "free with limits" can be priced from facts (2026-10-20).

Counts only. It never stores a prompt, an answer, a line of code, a repository name, an email or an address. For each day it keeps a
handful of numbers in the existing `stats` table (key = "usage:<date>:<name>", value = a whole number):

  scan_calls    / scan_input_tokens    / scan_output_tokens      AI calls for visitors' free scans and their Part 2 fix prompts
  monitor_calls / monitor_input_tokens / monitor_output_tokens   the daily checks of our own apps (the landing-page badge)       [from 22 Oct 2026]
  deep_calls    / deep_input_tokens    / deep_output_tokens      deep scans                                                    [from 22 Oct 2026]
  ask_calls     / ask_input_tokens     / ask_output_tokens       the Ask Verilay question box
  scans_full / scans_replayed / scans_preview           finished free scans: analysed in full, replayed from a saved result (no AI), live-address preview
  scans_monitor / scans_monitor_skipped / scans_deep    own-app checks run, own-app checks skipped because the code had not changed, deep scans finished

Before 22 Oct 2026 the monitor's and the deep scans' AI calls were counted under "scan", so older days cannot be split.

The numbers are approximate on purpose: two workers can update the same number at the same moment and one update can be lost, and a
restart can lose the last few seconds. That is fine for working out an average. Nothing here can slow down or break a scan: every call is
best effort and swallows its own errors.

To turn tokens into money, set AI_PRICE_INPUT_PER_MTOK and AI_PRICE_OUTPUT_PER_MTOK on Railway (US dollars per million tokens, from the
price list for the model in use). With no prices set, only tokens are shown: no price is guessed here.
"""
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta

KINDS = ("scan", "ask", "monitor", "deep", "pro")
SCAN_SOURCES = ("monitor", "deep", "pro")           # what a scan-type AI call can be attributed to, besides a visitor's free scan
SCAN_KINDS = ("full", "replayed", "preview", "monitor", "monitor_skipped", "deep", "pro")
LABELS = {"scan": "Free scans (visitors)", "monitor": "Monitoring our own apps", "deep": "Deep scans", "ask": "Ask Verilay questions",
          "pro": "Pro scans (free during launch)"}
UNIT = {"scan": "full", "monitor": "monitor", "deep": "deep", "pro": "pro"}    # which finished-scan counter divides each cost
FLUSH_EVERY_SECONDS = 60
MAX_PENDING_KEYS = 200

_lock = threading.Lock()
_local = threading.local()
_pending = {}
_last_flush = 0.0
_get_sb = lambda: None


@contextmanager
def attribute(source):
    """Inside the block, AI calls made by THIS thread that would count as a visitor's scan are counted under `source` instead
    ("monitor" or "deep"). Anything else is ignored. The previous setting is always restored, even on an error."""
    prev = getattr(_local, "source", None)
    if source in SCAN_SOURCES:
        _local.source = source
    try:
        yield
    finally:
        _local.source = prev


def current_source():
    return getattr(_local, "source", None)


def set_source(source):
    """Set this thread's source (None clears it) and return the previous one, for code that cannot use attribute()
    (a streaming generator, a worker thread)."""
    prev = getattr(_local, "source", None)
    _local.source = source if source in SCAN_SOURCES else None
    return prev


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


# Prices (US$ per million tokens) for models whose price differs from the Railway setting. A call to one of these is
# costed at its own price and stored as "<kind>_cost_micro" (millionths of a dollar) with the tokens it covers
# ("<kind>_priced_input_tokens" / "_priced_output_tokens"); every other call is costed with AI_PRICE_* as before.
MODEL_PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),     # prompts up to 100K tokens (Anthropic price list, Oct 2026)
    "claude-sonnet-5-5": (2.00, 10.00),
}


def record(input_tokens=None, output_tokens=None, kind="scan", now=None, model=None):
    """One AI call. Token counts may be unknown (None); the call is still counted. Never raises."""
    try:
        if kind not in KINDS:
            return
        if kind == "scan" and current_source() in SCAN_SOURCES:
            kind = current_source()
        _bump(f"{kind}_calls", 1, now)
        if isinstance(input_tokens, int):
            _bump(f"{kind}_input_tokens", input_tokens, now)
        if isinstance(output_tokens, int):
            _bump(f"{kind}_output_tokens", output_tokens, now)
        price = MODEL_PRICES.get(model or "")
        if price and isinstance(input_tokens, int) and isinstance(output_tokens, int):
            _bump(f"{kind}_cost_micro", int(round(input_tokens * price[0] + output_tokens * price[1])), now)
            _bump(f"{kind}_priced_input_tokens", input_tokens, now)
            _bump(f"{kind}_priced_output_tokens", output_tokens, now)
        _maybe_flush()
    except Exception:
        pass


def record_from_stream(stream, kind="scan", model=None):
    """Read the token counts from a finished Anthropic streaming call. Counts only; never touches the text. Never raises."""
    try:
        usage = stream.get_final_message().usage
        record(getattr(usage, "input_tokens", None), getattr(usage, "output_tokens", None), kind, model=model)
    except Exception:
        record(None, None, kind, model=model)


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


def _cost(d, prices, kinds=KINDS):
    """Calls to a model in MODEL_PRICES are costed at their own price (cost_micro); the rest at the Railway prices."""
    total = 0.0
    for k in kinds:
        tin = d.get(f"{k}_input_tokens", 0) - d.get(f"{k}_priced_input_tokens", 0)
        tout = d.get(f"{k}_output_tokens", 0) - d.get(f"{k}_priced_output_tokens", 0)
        total += max(0, tin) * prices[0] / 1e6 + max(0, tout) * prices[1] / 1e6 + d.get(f"{k}_cost_micro", 0) / 1e6
    return round(total, 4)


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
                d["est_cost_usd"] = _cost(d, prices)
            out_days.append({"date": day, **d})
            for k, v in d.items():
                tot[k] = tot.get(k, 0) + v
        full = tot.get("scans_full", 0)
        avg = {}
        if full:
            avg["scan_tokens_per_full_scan"] = round((tot.get("scan_input_tokens", 0) + tot.get("scan_output_tokens", 0)) / full)
            avg["scan_calls_per_full_scan"] = round(tot.get("scan_calls", 0) / full, 1)
            if prices:
                avg["est_cost_usd_per_full_scan"] = _cost(tot, prices, ("scan",)) / full
                avg["est_cost_usd_per_full_scan"] = round(avg["est_cost_usd_per_full_scan"], 4)
        return {"available": True, "days": out_days, "totals": tot, "averages": avg, "prices_set": bool(prices),
                "note": ("Approximate. Days before 22 Oct 2026 count own-app monitoring and deep scans under 'scan'; replayed scans use no AI. "
                         "Cost needs AI_PRICE_INPUT_PER_MTOK and AI_PRICE_OUTPUT_PER_MTOK to be set." if not prices else
                         "Approximate. Days before 22 Oct 2026 count own-app monitoring and deep scans under 'scan'; replayed scans use no AI.")}
    except Exception as e:
        return {"available": False, "reason": type(e).__name__}


def dashboard(days=30, now=None):
    """What the AI is costing, split by what it was used for, for the admin cost page. Plain data; never raises.

    Per category (free scans, monitoring, deep scans, Ask): AI calls, tokens, estimated cost, how many finished scans there were, and
    the cost of one. Also the per-day cost split, and a rough monthly figure from the days that have data. Hosting is added only when
    HOSTING_COST_USD_PER_MONTH is set. Never guesses: with no AI prices set, costs are None and only counts are shown."""
    base = summary(days, now)
    if not base.get("available"):
        return base
    prices = _prices()
    tot = base["totals"]
    cats = []
    for kind in ("scan", "monitor", "deep", "pro", "ask"):
        calls = tot.get(f"{kind}_calls", 0)
        tin, tout = tot.get(f"{kind}_input_tokens", 0), tot.get(f"{kind}_output_tokens", 0)
        units = tot.get({"scan": "scans_full", "monitor": "scans_monitor", "deep": "scans_deep", "pro": "scans_pro"}.get(kind, ""), 0)
        cost = _cost(tot, prices, (kind,)) if prices else None
        cats.append({"kind": kind, "label": LABELS[kind], "calls": calls, "input_tokens": tin, "output_tokens": tout, "cost_usd": cost,
                     "units": units, "cost_per_unit_usd": round(cost / units, 4) if (cost is not None and units) else None})
    day_rows = []
    for d in base["days"]:
        row = {"date": d["date"], "total_usd": d.get("est_cost_usd")}
        for kind in ("scan", "monitor", "deep", "pro", "ask"):
            row[kind] = _cost(d, prices, (kind,)) if prices else None
        day_rows.append(row)
    total_cost = round(sum(c["cost_usd"] for c in cats), 4) if prices else None
    n_days = len(base["days"])
    per_month = round(total_cost / n_days * 30, 2) if (prices and n_days) else None
    try:
        hosting = float(os.getenv("HOSTING_COST_USD_PER_MONTH", "").strip())
    except Exception:
        hosting = None
    return {"available": True, "days_with_data": n_days, "window_days": days, "categories": cats, "per_day": day_rows,
            "total_usd": total_cost, "estimated_per_month_usd": per_month, "hosting_per_month_usd": hosting,
            "all_in_per_month_usd": round(per_month + hosting, 2) if (per_month is not None and hosting is not None) else None,
            "own_app_checks_skipped": tot.get("scans_monitor_skipped", 0), "prices_set": bool(prices),
            "note": base["note"]}


# ── Today's spend, for the daily AI budget (25 Oct 2026) ──────────────────────
TODAY_CACHE_SECONDS = 60
_today_cache = {"at": 0.0, "day": "", "rows": None}


def budget_usd():
    """The daily AI budget in US dollars (Railway setting VERILAY_DAILY_AI_BUDGET_USD, default 15). 0 or less turns it off."""
    try:
        v = float(os.getenv("VERILAY_DAILY_AI_BUDGET_USD", "15").strip() or "15")
    except Exception:
        v = 15.0
    return v if v > 0 else None


def today_cost_usd(now=None, kinds=KINDS):
    """Estimated AI spend so far today (UTC), all kinds together: what the database holds plus what this worker has not
    written yet. The database part is re-read at most once a minute. None when no AI prices are set (nothing is guessed)
    or the database cannot be reached. Never raises."""
    try:
        prices = _prices()
        if not prices:
            return None
        day = _today(now)
        t = time.time()
        if _today_cache["day"] != day or _today_cache["rows"] is None or t - _today_cache["at"] >= TODAY_CACHE_SECONDS:
            sb = _get_sb()
            if sb is None:
                return None
            rows = sb.table("stats").select("key,value").like("key", f"usage:{day}:%").execute().data or []
            _today_cache.update(at=t, day=day, rows=rows)
        d = {}
        for r in _today_cache["rows"]:
            name = str(r.get("key", "")).split(":", 2)[-1]
            d[name] = d.get(name, 0) + int(r.get("value") or 0)
        prefix = f"usage:{day}:"
        with _lock:
            for key, v in _pending.items():
                if key.startswith(prefix):
                    d[key[len(prefix):]] = d.get(key[len(prefix):], 0) + v
        return _cost(d, prices, kinds)
    except Exception:
        return None


def over_budget(now=None):
    """(True, spent, budget) when today's AI spend has reached the daily budget; (False, spent, budget) otherwise.
    Fails open: with no prices, no database or no budget, it never blocks."""
    b = budget_usd()
    spent = today_cost_usd(now)
    if b is None or spent is None:
        return False, spent, b
    return spent >= b, spent, b
