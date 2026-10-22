"""verilay_platformcheck.py - does every service Verilay stands on still work the way Verilay expects? (2026-10-21)

Platforms change under us (Supabase stopped granting new tables on 30 Oct 2026; AI models get retired; GitHub retires API versions). Most
of those changes are announced by email, and an email can be missed. This page does not predict anything: it TRIES each thing Verilay
needs, for real, and says which one stopped working and what to do about it. Run it after any platform notice, after any deploy, and
now and then.

Admin only (a signed-in admin, or a request carrying the secret VERILAY_HEALTH_TOKEN in a header). Everyone else gets "Not found".
It reports yes/no and a short plain reason. It never shows a key, a token, an email address, a report or a repository name.

What it does to your data: it reads one row from each table, and writes then deletes ONE test row (key "healthcheck:canary") in `stats`.
It sends the AI a few words, which costs a fraction of a cent. The answer is kept for two minutes so reloading the page costs nothing.
"""
import hmac
import html
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

import requests as http      # a name tests can replace

# Every table Verilay's code reads or writes. A test compares this list with the code, so a new table cannot be forgotten.
TABLES = ("ask_usage", "deepscan_jobs", "deepscan_prompts", "monitoring_interest", "private_repo_interest",
          "purchases", "reports", "scan_cache", "self_monitoring", "stats", "waitlist")

# The AI model the scans use. A test checks it matches the model written in app.py.
MODEL = "claude-sonnet-4-5"
ANTHROPIC_VERSION = "2023-06-01"

# Retirement dates Anthropic has announced (platform.claude.com/docs/en/about-claude/model-deprecations, read 21 Oct 2026). When a model is
# deprecated, add it here: the page then counts down and goes red on the day. model -> (retirement date, the replacement they recommend).
MODEL_RETIREMENTS = {"claude-sonnet-4-5": ("2026-11-30", "claude-sonnet-5-5")}
WARN_DAYS_BEFORE = 60

CANARY_KEY = "healthcheck:canary"
CACHE_SECONDS = 120
BUDGET_SECONDS = 40
SECRET_NAMES = ("ANTHROPIC_API_KEY", "SUPABASE_KEY", "SUPABASE_ANON_KEY", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "GITHUB_TOKEN",
                "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_CLIENT_SECRET", "SECRET_KEY", "VERILAY_HEALTH_TOKEN")

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skipped"

_deps = {"get_sb": lambda: None, "is_admin": lambda: False, "anthropic_key": lambda: "", "github_token": lambda: "", "billing": None}
_cache = {"at": 0.0, "data": None}
_lock = threading.Lock()


def init(app, get_sb, is_admin, anthropic_key, github_token, billing=None):
    """Hand over what the checks need. Everything is a function, resolved only when a check runs."""
    _deps.update(get_sb=get_sb, is_admin=is_admin, anthropic_key=anthropic_key, github_token=github_token, billing=billing)
    app.add_url_rule("/platform-health", "platform_health", platform_health)


# ── keeping secrets out of what we show ─────────────────────────────────────

def scrub(text, limit=180):
    """A short, safe version of an error message: no key, token or long secret-looking string can get through."""
    s = " ".join(str(text).split())
    for name in SECRET_NAMES:
        v = (os.getenv(name) or "").strip()
        if len(v) >= 8:
            s = s.replace(v, "***")
    s = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "***", s)
    s = re.sub(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-.]+", "***", s)
    s = re.sub(r"(?i)(bearer|token|key)[ :=]+[A-Za-z0-9_\-./+=]{16,}", r"\1 ***", s)
    return s[:limit]


def _res(status, detail, hint=""):
    return {"status": status, "detail": scrub(detail), "hint": hint}


# ── the checks. Each returns {"status","detail","hint"}; none raises past run_checks ──

def check_table(name):
    sb = _deps["get_sb"]()
    if sb is None:
        return _res(FAIL, "no database connection", "SUPABASE_URL or SUPABASE_KEY is missing or wrong on Railway.")
    try:
        r = sb.table(name).select("*").limit(1).execute()
        return _res(OK, "readable")
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        low = msg.lower()
        if "permission denied" in low or "42501" in low:
            return _res(FAIL, "permission denied",
                        f"The server is not allowed to use the '{name}' table. Since 30 Oct 2026 Supabase needs an explicit grant: in the Supabase "
                        f"SQL Editor run  grant select, insert, update, delete on public.{name} to service_role;")
        if "does not exist" in low or "42p01" in low or "pgrst205" in low or "could not find the table" in low:
            return _res(FAIL, "table not found", f"The '{name}' table is missing from this Supabase project.")
        if "jwt" in low or "invalid api key" in low or "apikey" in low:
            return _res(FAIL, "the database key was refused", "SUPABASE_KEY on Railway is wrong or has been replaced in Supabase.")
        return _res(FAIL, msg, "The table could not be read. Check the Supabase project is running.")


def check_db_write():
    sb = _deps["get_sb"]()
    if sb is None:
        return _res(FAIL, "no database connection")
    inserted = False
    try:
        sb.table("stats").delete().eq("key", CANARY_KEY).execute()      # a leftover from an earlier run
        sb.table("stats").insert({"key": CANARY_KEY, "value": 1}).execute()
        inserted = True
        back = sb.table("stats").select("value").eq("key", CANARY_KEY).execute().data or []
        if not back:
            return _res(FAIL, "wrote a test row but could not read it back")
        return _res(OK, "write, read and delete all work")
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        hint = "Verilay could not write to the database. Counters and saved reports would silently stop."
        if "permission denied" in msg.lower() or "42501" in msg:
            hint = ("The server may read but not write. Run in the Supabase SQL Editor:  "
                    "grant select, insert, update, delete on public.stats to service_role;")
        return _res(FAIL, msg, hint)
    finally:
        if inserted:
            try:
                sb.table("stats").delete().eq("key", CANARY_KEY).execute()
            except Exception:
                pass


def check_supabase_auth():
    url = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
    key = (os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_KEY") or "").strip()
    if not url or not key:
        return _res(SKIP, "not configured")
    try:
        r = http.get(url + "/auth/v1/health", headers={"apikey": key}, timeout=10)
    except Exception as e:
        return _res(FAIL, f"could not reach it: {type(e).__name__}", "Supabase sign-in could not be reached. Check status.supabase.com.")
    if r.status_code == 200:
        return _res(OK, "sign-in service answers")
    return _res(FAIL, f"answered with status {r.status_code}", "Sign-in emails may not work. Check Supabase auth settings and status.supabase.com.")


def _today():
    return datetime.now(timezone.utc).date()


def retirement_note(model=None):
    """None when the model has no announced retirement; otherwise (status, sentence). A warning for 60 days before, a failure from the day."""
    model = model or MODEL
    if model not in MODEL_RETIREMENTS:
        return None
    when, repl = MODEL_RETIREMENTS[model]
    days = (datetime.strptime(when, "%Y-%m-%d").date() - _today()).days
    nice = datetime.strptime(when, "%Y-%m-%d").strftime("%d %b %Y").lstrip("0")
    if days <= 0:
        return FAIL, f"{model} was retired on {nice}", (f"Every scan will fail. Move to {repl} now. Newer models refuse the temperature=0 setting the scans use, so remove it when you switch.")
    if days <= WARN_DAYS_BEFORE:
        return WARN, f"{model} is retired on {nice} ({days} days left)", (
            f"Anthropic's recommended replacement is {repl}. Switching is not just a name change: newer models refuse the setting temperature=0 that "
            "the scans use, and answers will differ, so test first and bump ANALYSIS_VERSION.")
    return None


def check_anthropic():
    key = _deps["anthropic_key"]()
    if not key:
        return _res(FAIL, "no ANTHROPIC_API_KEY", "Add ANTHROPIC_API_KEY on Railway. Without it no scan can run.")
    try:
        r = http.post("https://api.anthropic.com/v1/messages",
                      headers={"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json"},
                      json={"model": MODEL, "max_tokens": 8, "messages": [{"role": "user", "content": "Reply with the single word: ok"}]},
                      timeout=25)
    except Exception as e:
        return _res(WARN, f"could not reach it: {type(e).__name__}", "Anthropic did not answer. Try again in a few minutes and check status.anthropic.com.")
    c = r.status_code
    if c == 200:
        note = retirement_note()
        return _res(note[0], note[1], note[2]) if note else _res(OK, f"model {MODEL} answers")
    if c == 404:
        return _res(FAIL, f"model {MODEL} was not found",
                    f"The AI model '{MODEL}' has probably been retired. Every scan will fail. Pick the current model from Anthropic's model list "
                    "and change it in app.py (and in this file's MODEL line).")
    if c in (401, 403):
        return _res(FAIL, f"the key was refused (status {c})", "ANTHROPIC_API_KEY is wrong, revoked, or the account has no credit. Check console.anthropic.com.")
    if c == 400:
        return _res(FAIL, "the request was refused as invalid (status 400)",
                    "Anthropic may have changed what it accepts, or the account has no credit. Read the message at console.anthropic.com.")
    if c == 429 or c >= 500:
        return _res(WARN, f"busy or rate limited (status {c})", "Probably temporary. Run this page again in a few minutes.")
    return _res(FAIL, f"unexpected status {c}")


def _github_headers():
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "verilay-platform-check"}
    tok = _deps["github_token"]()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _sunset_note(headers):
    """GitHub marks a retiring API version or endpoint with Deprecation / Sunset headers."""
    try:
        low = {str(k).lower(): v for k, v in dict(headers or {}).items()}
    except Exception:
        return ""
    bits = []
    if low.get("deprecation"):
        bits.append("Deprecation: " + str(low["deprecation"]))
    if low.get("sunset"):
        bits.append("Sunset: " + str(low["sunset"]))
    return "; ".join(bits)


def check_github_api():
    try:
        r = http.get("https://api.github.com/rate_limit", headers=_github_headers(), timeout=12)
    except Exception as e:
        return _res(WARN, f"could not reach it: {type(e).__name__}", "GitHub did not answer. Check githubstatus.com.")
    if r.status_code == 401:
        return _res(FAIL, "GITHUB_TOKEN was refused", "The GITHUB_TOKEN on Railway has expired or been revoked. Public repo scans will hit low limits. Make a new one.")
    if r.status_code != 200:
        return _res(WARN, f"answered with status {r.status_code}")
    note = _sunset_note(r.headers)
    if note:
        return _res(WARN, "GitHub is retiring something we use (" + note + ")", "Read GitHub's changelog (github.blog/changelog) for what is ending and when.")
    left = ""
    try:
        left = f", {r.json()['resources']['core']['remaining']} requests left this hour"
    except Exception:
        pass
    return _res(OK, "answers" + left)


def check_github_app():
    import verilay_ghapp as gh
    if not gh.configured():
        return _res(SKIP, "private-repo app not configured")
    try:
        jwt_token = gh.app_jwt()
    except Exception as e:
        return _res(FAIL, "could not sign as the GitHub App: " + str(getattr(e, "detail", "") or type(e).__name__),
                    "GITHUB_APP_PRIVATE_KEY on Railway looks wrong or cut short. Paste the whole .pem file again.")
    try:
        r = http.get("https://api.github.com/app", headers={**_github_headers(), "Authorization": f"Bearer {jwt_token}"}, timeout=12)
    except Exception as e:
        return _res(WARN, f"could not reach it: {type(e).__name__}")
    if r.status_code == 200:
        note = _sunset_note(r.headers)
        return _res(WARN, "GitHub is retiring something we use (" + note + ")", "Read github.blog/changelog.") if note else _res(OK, "the App's key and ID are accepted")
    if r.status_code in (401, 403):
        return _res(FAIL, f"GitHub refused the App's key (status {r.status_code})",
                    "Private scans will fail. Check GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY on Railway match the App's page on GitHub.")
    return _res(WARN, f"answered with status {r.status_code}")


def check_osv():
    try:
        r = http.post("https://api.osv.dev/v1/query", json={"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "0.12"}, timeout=15)
    except Exception as e:
        return _res(WARN, f"could not reach it: {type(e).__name__}", "The known-vulnerability list (OSV) did not answer; dependency checks would be skipped. Try again later.")
    if r.status_code != 200:
        return _res(FAIL, f"answered with status {r.status_code}", "The dependency vulnerability service changed or is down. Dependency checks may be silently empty.")
    try:
        vulns = r.json().get("vulns")
    except Exception:
        vulns = None
    if not isinstance(vulns, list) or not vulns:
        return _res(FAIL, "answered, but not with the list we expect",
                    "Flask 0.12 is known to have vulnerabilities, so an empty or different answer means OSV changed its format. Dependency checks could report 'nothing found' wrongly.")
    return _res(OK, "answers, and finds known problems in an old library as expected")


def check_stripe():
    """The Stripe key is what matters. A price id is optional: without STRIPE_PRICE_ID the checkout builds the price itself."""
    b = _deps["billing"]
    key = (getattr(b, "STRIPE_SECRET_KEY", "") or "") if b is not None else ""
    if not key:
        return _res(SKIP, "no Stripe key set, so payments are not set up")
    st = getattr(b, "_stripe", None)
    if st is None:
        return _res(FAIL, "the Stripe library is not installed")
    mode = "live" if key.startswith(("sk_live", "rk_live")) else "test"
    price_id = (getattr(b, "STRIPE_PRICE_ID", "") or "").strip()
    try:
        if price_id:
            price = st.Price.retrieve(price_id)
            active = price["active"] if not hasattr(price, "active") else price.active
            if not active:
                return _res(FAIL, "the price is archived in Stripe", "Customers could not buy. Un-archive it or make a new price and update STRIPE_PRICE_ID.")
            what = "the saved price is active"
        else:
            st.Balance.retrieve()
            what = "no saved price needed, the checkout builds it"
    except Exception as e:
        low = f"{type(e).__name__}: {e}".lower()
        if "no such price" in low:
            return _res(FAIL, "the price was not found", "STRIPE_PRICE_ID is from a different Stripe account or mode than STRIPE_SECRET_KEY.")
        if "invalid api key" in low or "authentication" in low:
            return _res(FAIL, "the Stripe key was refused", "STRIPE_SECRET_KEY is wrong or has been rolled in the Stripe dashboard.")
        if "permission" in low:
            what = "key accepted (a restricted key that may not read the balance)"
        else:
            return _res(WARN, f"{type(e).__name__}", "Stripe did not answer as expected. Check status.stripe.com.")
    if not (getattr(b, "STRIPE_WEBHOOK_SECRET", "") or "").strip():
        return _res(WARN, f"{mode} mode, key accepted, but no webhook secret",
                    "Without STRIPE_WEBHOOK_SECRET a payment is taken but the purchase is never recorded. Add it from the Stripe dashboard (Developers, Webhooks).")
    return _res(OK, f"{mode} mode, key accepted, {what}, webhook secret set")


def check_settings():
    missing = [n for n in ("ANTHROPIC_API_KEY", "SUPABASE_URL", "SUPABASE_KEY", "SECRET_KEY") if not (os.getenv(n) or "").strip()]
    if missing:
        return _res(FAIL, "missing on Railway: " + ", ".join(missing), "Add the missing variables on Railway. Names only are shown here, never values.")
    return _res(OK, "all four required settings are present")


def check_versions():
    """Information, not a test: what we are running on, so a platform notice can be compared with it."""
    try:
        from importlib.metadata import version
    except Exception:
        return _res(OK, "")
    parts = [f"python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"]
    for lib in ("flask", "anthropic", "supabase", "stripe", "requests", "gunicorn"):
        try:
            parts.append(f"{lib} {version(lib)}")
        except Exception:
            parts.append(f"{lib} -")
    return _res(OK, ", ".join(parts))


def _plan():
    out = [("Settings present", check_settings),
           ("Database write test", check_db_write),
           ("AI model", check_anthropic),
           ("GitHub API", check_github_api),
           ("GitHub App (private repos)", check_github_app),
           ("Vulnerability list (OSV)", check_osv),
           ("Sign-in service (Supabase)", check_supabase_auth),
           ("Payments (Stripe)", check_stripe)]
    out += [(f"Table: {t}", (lambda t=t: check_table(t))) for t in TABLES]
    out.append(("What we are running on", check_versions))
    return out


def run_checks(budget=None):
    """Run every check at the same time. A check that raises or hangs becomes a failure; the whole run is bounded."""
    budget = BUDGET_SECONDS if budget is None else budget
    plan = _plan()
    pool = ThreadPoolExecutor(max_workers=12)
    started = time.time()
    futs = []
    for name, fn in plan:
        def wrapped(fn=fn):
            t0 = time.time()
            try:
                r = fn()
            except Exception as e:
                r = _res(FAIL, f"the check itself crashed: {type(e).__name__}: {e}")
            r["ms"] = int((time.time() - t0) * 1000)
            return r
        futs.append((name, pool.submit(wrapped)))
    wait([f for _, f in futs], timeout=budget)
    checks = []
    for name, f in futs:
        if f.done():
            try:
                r = f.result()
            except Exception as e:
                r = _res(FAIL, f"the check itself crashed: {type(e).__name__}")
        else:
            r = _res(FAIL, f"no answer within {int(budget)} seconds", "That service is very slow or not answering. Try again in a few minutes.")
        checks.append({"name": name, **r})
    pool.shutdown(wait=False)
    bad = [c for c in checks if c["status"] == FAIL]
    warn = [c for c in checks if c["status"] == WARN]
    return {"ok": not bad, "failed": len(bad), "warnings": len(warn),
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "took_seconds": round(time.time() - started, 1), "checks": checks}


def cached_run():
    """The last answer if it is under two minutes old; otherwise a fresh run. Reloading the page cannot run up a bill."""
    with _lock:
        if _cache["data"] is not None and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["data"]
    data = run_checks()
    with _lock:
        _cache["data"], _cache["at"] = data, time.time()
    return data


def _token_ok(req):
    want = (os.getenv("VERILAY_HEALTH_TOKEN") or "").strip()
    got = (req.headers.get("X-Health-Token") or "").strip()
    return bool(want) and len(want) >= 16 and bool(got) and hmac.compare_digest(want.encode(), got.encode())


def render_html(data):
    esc = html.escape
    icon = {OK: "&#10003;", WARN: "!", FAIL: "&#10007;", SKIP: "&ndash;"}
    colour = {OK: "#1D9E75", WARN: "#b7791f", FAIL: "#c0392b", SKIP: "#8a8884"}
    rows = []
    for c in data["checks"]:
        s = c["status"]
        hint = f'<div class="hint">{esc(c["hint"])}</div>' if c.get("hint") and s in (FAIL, WARN) else ""
        rows.append(f'<div class="row"><span class="ic" style="color:{colour[s]}">{icon[s]}</span><div><b>{esc(c["name"])}</b>'
                    f' <span class="d">{esc(c["detail"])}</span>{hint}</div></div>')
    if data["ok"] and not data["warnings"]:
        head = '<h1 style="color:#1D9E75">Everything Verilay depends on is working</h1>'
    elif data["ok"]:
        head = f'<h1 style="color:#b7791f">Working, with {data["warnings"]} thing(s) to look at</h1>'
    else:
        head = f'<h1 style="color:#c0392b">{data["failed"]} thing(s) not working</h1>'
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="robots" content="noindex"><title>Platform check - Verilay</title><style>'
            'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;margin:0;font-size:15px}'
            '.w{max-width:720px;margin:0 auto;padding:1.5rem 16px}h1{font-size:22px;margin:.2rem 0 .3rem}'
            '.row{display:flex;gap:10px;padding:9px 0;border-bottom:.5px solid #e8e6e0}.ic{font-weight:700;width:16px;flex:none}'
            '.d{color:#6b6966;font-size:13px}.hint{font-size:13px;margin-top:3px;color:#4a4846}.m{color:#6b6966;font-size:13px}'
            '</style></head><body><div class="w">' + head +
            f'<p class="m">Checked {esc(data["checked_at"])} in {data["took_seconds"]}s. Each line is a real test, not a guess. Shown for two minutes after a run.</p>'
            + "".join(rows) + '</div></body></html>')


def platform_health():
    from flask import request, jsonify, Response
    if not (_deps["is_admin"]() or _token_ok(request)):
        return "Not found", 404
    data = cached_run()
    wants_html = "text/html" in (request.headers.get("Accept") or "") and request.args.get("format") != "json"
    if wants_html:
        resp = Response(render_html(data), mimetype="text/html")
    else:
        resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex"
    return resp
