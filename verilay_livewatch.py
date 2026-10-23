"""verilay_livewatch.py - a free daily look at each monitored app's LIVE site (23 Oct 2026).

Why: Verilay's check of an app reads its code. Browser-protection headers, the https redirect and the certificate are not in the code; they
are what the running site sends. A scan of verilay.dev from outside found no headers at all while Verilay's own scan of its own code said A.
So each monitored app that has a live address also gets this small check, once a day:

  * which of the six browser-protection headers the live site sends
  * whether plain http:// is sent on to https://
  * how many days are left on the site's certificate

No AI, no code reading, no cost. It fetches one page, the way a browser does, through the same safe-fetch guard every visitor-supplied
address goes through. Admin only: the result shows in the monitored-apps table and is never shown publicly.

When Moses is emailed: only when something CHANGES for the worse, never a daily "all fine". A header that was seen before and is gone, an
https redirect that stopped, a certificate with 14 days or fewer left. The first check only records a baseline, so a site that never sent
a header (a builder-hosted app, say) does not email on day one. A problem that stays is mentioned again after a week, until it is fixed.
An unreachable site is recorded but not emailed (the uptime monitor's job).

Needs three columns on self_monitoring (supabase_self_monitoring_live.sql). Without them it logs one line and does nothing.
"""
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from html import escape

import verilay_url_guard as guard

SITE_HEADERS = ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
                "Content-Security-Policy")
CHECK_INTERVAL_HOURS = 24
CERT_WARN_DAYS = 14
REALERT_DAYS = 7
TIMEOUT = 15
USER_AGENT = "verilay-livewatch (checks our own sites)"
_warned = {"columns": False}
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc)


# ── fetching ─────────────────────────────────────────────────────────────────

def _plain_get(url):
    import requests
    return requests.get(url, allow_redirects=False, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})


def _cert_days(host, now=None):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    return (expires - (now or _now())).days


def fetch_live(url, now=None, get=None, get_plain=None, cert_days=None):
    """One look at a live address. Never raises: a failure comes back as {"error": "..."}. The three network steps can be replaced (tests)."""
    now = now or _now()
    out = {"url": url, "at": now.isoformat(), "status": None, "present": [], "https_redirect": None, "cert_days": None, "error": None}
    try:
        if not isinstance(url, str) or not url.startswith("https://"):
            out["error"] = "the live address must start with https://"
            return out
        host, _ips = guard.validate_url(url)          # refuses private and internal addresses
        resp = (get or guard.safe_get)(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        out["status"] = resp.status_code
        have = {str(k).lower() for k in dict(resp.headers or {})}
        out["present"] = [h for h in SITE_HEADERS if h.lower() in have]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:160]
        return out
    try:                                              # the next two are extras: a failure leaves them unknown, not wrong
        plain = "http://" + url[len("https://"):]
        guard.validate_url(plain)
        r = (get_plain or _plain_get)(plain)
        loc = (r.headers or {}).get("Location", "") if hasattr(r, "headers") else ""
        out["https_redirect"] = bool(r.status_code in (301, 302, 303, 307, 308) and str(loc).lower().startswith("https://"))
    except Exception:
        out["https_redirect"] = None
    try:
        out["cert_days"] = (cert_days or _cert_days)(host)
    except Exception:
        out["cert_days"] = None
    return out


# ── deciding what is news ────────────────────────────────────────────────────

def evaluate(prev, result, now=None):
    """(new_state, problems). problems is [(key, sentence)] that should be emailed NOW. Pure: no network, no database."""
    now = now or _now()
    prev = dict(prev or {})
    state = dict(prev)
    state.update({"checked_at": result.get("at") or now.isoformat(), "url": result.get("url"), "status": result.get("status"), "error": result.get("error")})
    alerted = dict(prev.get("alerted") or {})
    if result.get("error"):
        state["alerted"] = alerted
        return state, []                                # unreachable: recorded, never emailed; the baseline is kept as it was

    present = list(result.get("present") or [])
    expected = sorted(set(prev.get("expected") or []) | set(present), key=SITE_HEADERS.index)
    missing_now = [h for h in SITE_HEADERS if h not in present]
    lost = [h for h in expected if h not in present]
    state.update({"present": present, "missing": missing_now, "expected": expected,
                  "https_redirect": result.get("https_redirect"), "cert_days": result.get("cert_days")})
    if result.get("https_redirect") is True:
        state["https_expected"] = True
    elif result.get("https_redirect") is None:
        state["https_redirect"] = prev.get("https_redirect")           # could not tell: keep what was known

    current = {}
    for h in lost:
        current["header:" + h] = f"{h} was being sent and is not any more"
    if state.get("https_expected") and result.get("https_redirect") is False:
        current["https"] = "http:// no longer sends visitors on to https://"
    days = result.get("cert_days")
    if isinstance(days, int) and days <= CERT_WARN_DAYS:
        current["cert"] = (f"the certificate expires in {days} day{'s' if days != 1 else ''}" if days >= 0 else "the certificate has expired")

    to_send = []
    for key, sentence in current.items():
        last = alerted.get(key)
        age_ok = True
        if last:
            try:
                age_ok = now - datetime.fromisoformat(last) >= timedelta(days=REALERT_DAYS)
            except Exception:
                age_ok = True
        if age_ok:
            to_send.append((key, sentence))
            alerted[key] = now.isoformat()
    for key in list(alerted):
        if key not in current:
            del alerted[key]                            # fixed: forget it, so a later return of the problem emails again
    state["alerted"] = alerted
    return state, to_send


# ── the daily round ──────────────────────────────────────────────────────────

def tick(sb, alert, now=None, **fetchers):
    """Check at most ONE app that is due. Safe to call from every worker: the claim is a conditional update, so two workers
    cannot both take the same app. Returns the app name checked, or None. Never raises."""
    if sb is None:
        return None
    now = now or _now()
    try:
        cutoff = (now - timedelta(hours=CHECK_INTERVAL_HOURS)).isoformat()
        try:
            rows = (sb.table("self_monitoring").select("app_name,live_url,live_state,live_checked_at")
                      .lt("live_checked_at", cutoff).order("live_checked_at").limit(20).execute().data or [])
        except Exception as e:
            with _lock:
                if not _warned["columns"]:
                    _warned["columns"] = True
                    print(f"[livewatch] skipped (run supabase_self_monitoring_live.sql?): {type(e).__name__}", flush=True)
            return None
        row = next((r for r in rows if (r.get("live_url") or "").strip()), None)
        if not row:
            return None
        claim = (sb.table("self_monitoring").update({"live_checked_at": now.isoformat()})
                   .eq("app_name", row["app_name"]).lt("live_checked_at", cutoff).execute())
        if not claim.data:
            return None                                  # another worker took it a moment ago
        url = row["live_url"].strip()
        result = fetch_live(url, now=now, **fetchers)
        state, problems = evaluate(row.get("live_state"), result, now)
        sb.table("self_monitoring").update({"live_state": state}).eq("app_name", row["app_name"]).execute()
        if problems:
            try:
                alert(row["app_name"], url, [s for _k, s in problems])
            except Exception as e:
                print(f"[livewatch] alert failed for {row['app_name']}: {type(e).__name__}", flush=True)
        print(f"[livewatch] {row['app_name']}: {len(state.get('present') or [])}/{len(SITE_HEADERS)} headers"
              f"{', ' + str(len(problems)) + ' new problem(s)' if problems else ''}"
              f"{', ' + state['error'] if state.get('error') else ''}", flush=True)
        return row["app_name"]
    except Exception as e:
        print(f"[livewatch] round failed (non-critical): {type(e).__name__}: {e}", flush=True)
        return None


# ── what the admin table shows ───────────────────────────────────────────────

def _ago(iso, now=None):
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        h = ((now or _now()) - t).total_seconds() / 3600
        return "just now" if h < 1 else (f"{int(h)} h ago" if h < 48 else f"{int(h // 24)} days ago")
    except Exception:
        return ""


def summary_html(row, now=None):
    """The 'Live site' cell for the admin monitored-apps table. Everything is escaped."""
    note = 'style="color:#6b6966;font-size:12px"'
    if not (row.get("live_url") or "").strip():
        return f'<span {note}>no live address set</span>'
    st = row.get("live_state") or {}
    if not st:
        return f'<span {note}>waiting for the first check</span>'
    if st.get("error") and not st.get("present") and not st.get("expected"):
        return f'<span style="color:#A32D2D;font-size:12px">&#9888; could not check: {escape(str(st["error"])[:90])}</span>'
    n = len(st.get("present") or [])
    miss = [h for h in SITE_HEADERS if h not in (st.get("present") or [])]
    colour = "#1D9E75" if not miss else ("#A32D2D" if st.get("expected") and set(miss) & set(st["expected"]) else "#92400E")
    parts = [f'<strong style="color:{colour}">{n}/{len(SITE_HEADERS)} headers</strong>']
    if miss:
        parts.append(f'<span {note}>missing: {escape(", ".join(miss))}</span>')
    if st.get("https_redirect") is True:
        parts.append(f'<span {note}>http goes to https &#10003;</span>')
    elif st.get("https_redirect") is False:
        parts.append('<span style="color:#A32D2D;font-size:12px">http does NOT go to https</span>')
    if isinstance(st.get("cert_days"), int):
        low = st["cert_days"] <= CERT_WARN_DAYS
        parts.append(f'<span style="color:{"#A32D2D" if low else "#6b6966"};font-size:12px">certificate {st["cert_days"]} days left</span>')
    if st.get("error"):
        parts.append(f'<span style="color:#A32D2D;font-size:12px">last check failed: {escape(str(st["error"])[:60])}</span>')
    ago = _ago(st.get("checked_at"), now)
    if ago:
        parts.append(f'<span {note}>checked {escape(ago)}</span>')
    return "<br>".join(parts)
