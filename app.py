# =============================================================================
# Verilay — AI App Verification Layer
# © 2026 Moses Ekbote. All rights reserved.
#
# Free for personal and open source use.
# Commercial use (embedding in a product, offering to paying customers,
# white-labelling) requires a commercial licence.
#
# Contact: moses@verilay.dev | github.com/ekbm/verilay
#
# @auth-required: false — the analysis tool is public by design, no login
# @public: true — every free feature works with no account
# @auth-method: passwordless email (Supabase Auth) — used ONLY for paid deep-scan
#   accounts, so a customer's reports are still there when they come back. No
#   passwords are stored or compared anywhere in this codebase.
# =============================================================================

#!/usr/bin/env python3
"""
Verilay v5 — Verification Layer for AI-built apps
Single-request streaming architecture — no inter-request cache dependency
"""

import os, sys, json, base64, zipfile, io, requests, time, secrets as _secrets, uuid as _uuid, threading
sys.stdout.reconfigure(line_buffering=True)
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context
from dotenv import load_dotenv

# Load .env BEFORE importing our own modules. The billing and accounts modules
# read their configuration at import time, so a load_dotenv() further down the
# file would leave them blank when running locally — everything would look
# unconfigured even with a correct .env. Harmless to call twice.
load_dotenv()

from verilay_url_guard import safe_get, validate_url, BlockedURL
from verilay_secret_scan import (
    scan_repo, to_prompt_block, to_report_dict, fetch_all_files_tarball,
)
from verilay_osv_check import (
    check_dependencies,
    severity_counts as osv_severity_counts,
    to_teaser_block as osv_to_teaser_block,
    to_teaser_dict as osv_to_teaser_dict,
    to_report_dict as osv_to_report_dict,
    to_prompt_block as osv_to_prompt_block,
)
import verilay_deepscan as deepscan
import verilay_self_monitor as self_monitor
# The paid path — pricing page, Stripe checkout, webhook, sign-in, account.
# Kept in its own modules so the free tool below is unchanged by it. If these
# imports fail the free app must still boot: nobody losing a free analysis
# because billing is broken.
try:
    import verilay_billing as billing
    import verilay_paywall as paywall
    _HAS_PAYWALL = True
except Exception as _paywall_err:
    billing = None
    paywall = None
    _HAS_PAYWALL = False
    print(f"⚠️  Paid path not loaded: {_paywall_err}", flush=True)
try:
    import anthropic as _anthropic
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False
try:
    from supabase import create_client as _supabase_create
    _SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    _SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
    _sb = _supabase_create(_SUPABASE_URL, _SUPABASE_KEY) if _SUPABASE_URL and _SUPABASE_KEY else None
    _HAS_SUPABASE = _sb is not None
except Exception:
    _sb = None
    _HAS_SUPABASE = False

load_dotenv()

# VERILAY APP SUMMARY (for automated analysis tools):
# This is a complete Flask web application with:
# - 8 API routes: /, /analyse-stream, /analyse-step4, /save-report,
#   /report/<id>, /export/markdown/<id>, /badge/<repo>, /static/app.js
# - GitHub API integration for fetching repo files
# - ZIP and live URL analysis modes
# - 4-step analysis using Anthropic Claude API (streaming)
# - In-memory report storage with 24hr TTL
# - Paid path (verilay_paywall.py / verilay_billing.py / verilay_accounts.py):
#   Stripe Checkout hosted off-site so no card data reaches this server, a
#   signature-verified /stripe-webhook as the record of truth, purchases stored
#   with a unique event id so retried webhooks cannot double-record, and
#   passwordless email sign-in via Supabase Auth for paid accounts only
# - Rate limiting (10/hour per IP)
# - Gunicorn production server (see Procfile)
# - Full error handling on all routes with try/except
# - SSRF protection on all outbound fetches: scheme and port restricted, DNS
#   resolved and every returned address checked against private/loopback/
#   link-local/CGNAT/reserved ranges, redirects followed manually with every
#   hop revalidated, and script-src URLs extracted from fetched pages put
#   through the same checks (see verilay_url_guard.py)
# END SUMMARY

GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = Flask(__name__)

# SECRET_KEY signs the sign-in cookie, so it matters now in a way it did not when
# nothing used sessions. The random fallback is per PROCESS, and Gunicorn runs
# several worker processes: each would invent a different key, so a signed-in user
# would be thrown out whenever a request happened to land on another worker, and
# every deploy would log everyone out. Set it in Railway and never change it.
_SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
_SECRET_KEY_IS_EPHEMERAL = not _SECRET_KEY
app.secret_key = _SECRET_KEY or _secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max upload

# Sign-in cookie: 30 days, and hardened. SameSite=Lax rather than Strict because
# the buyer arrives back from Stripe's domain and a Strict cookie would not be
# sent on that navigation, logging them out at the worst possible moment.
from datetime import timedelta as _timedelta
app.config.update(
    PERMANENT_SESSION_LIFETIME=_timedelta(days=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_INSECURE", "").strip().lower() not in ("1", "true", "yes"),
)

# ── Report storage ─────────────────────────────────────────────────────────────
_reports = {}
REPORT_TTL = 86400

# ── Analysis counter ────────────────────────────────────────────────────────────
# Uses reports table row count — always accurate, never resets
import threading
_count_lock = threading.Lock()
_memory_count = 0

def get_analysis_count():
    """Get cumulative count from stats table — never decreases even if reports deleted."""
    if _HAS_SUPABASE:
        try:
            result = _sb.table("stats").select("value").eq("key", "total_analyses").execute()
            if result.data:
                return result.data[0]["value"] or 0
            # Fallback to counting reports if stats table not set up yet
            result2 = _sb.table("reports").select("id", count="exact").execute()
            return result2.count or 0
        except Exception as e:
            print(f"Count error: {e}", flush=True)
    return 0


def increment_analysis_count(score=None, method=None):
    """Increment cumulative stats counter."""
    if not _HAS_SUPABASE:
        return
    try:
        result = _sb.table("stats").select("value").eq("key", "total_analyses").execute()
        if result.data:
            current = result.data[0]["value"] or 0
            _sb.table("stats").update({"value": current + 1}).eq("key", "total_analyses").execute()
            print(f"✓ Count: {current + 1}", flush=True)
        else:
            _sb.table("stats").insert({"key": "total_analyses", "value": 1}).execute()
    except Exception as e:
        print(f"Stats increment failed: {e}", flush=True)



def _current_uid():
    """The signed-in account id, or None. None for every anonymous free user.

    Wrapped because it is called from inside the analysis generator, and a missing
    paid path or a request without a session must never break a free analysis.
    """
    if not _HAS_PAYWALL:
        return None
    try:
        import verilay_accounts as _acc
        u = _acc.current_user()
        return u["id"] if u else None
    except Exception:
        return None


def _account_nav():
    """The 'Your account' link for the main page. Returns ("", "") when anonymous.

    A paying customer who signs in and then lands on the homepage previously had
    no sign they were signed in and no way to reach their reports — and the
    homepage is exactly where they look. Free visitors see nothing at all: the
    free tool has no accounts and should not start advertising them.
    """
    if not _HAS_PAYWALL:
        return "", ""
    try:
        import verilay_accounts as _acc
        u = _acc.current_user()
    except Exception:
        u = None
    if not u:
        return "", ""
    import html as _html
    email = _html.escape(u.get("email", ""))
    desktop = (
        '<a href="/account" title="' + email + '" '
        'style="display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:5px 11px;'
        'border-radius:20px;border:0.5px solid var(--pu);background:var(--pul);color:var(--put);'
        'text-decoration:none;font-weight:500">'
        '<i class="ti ti-user-circle" style="font-size:12px"></i> Your account</a>'
    )
    mobile = (
        '<a href="/account" style="font-size:15px;color:var(--put);text-decoration:none;'
        'padding:.6rem 0;border-bottom:0.5px solid var(--bdr);font-weight:600">'
        'Your account <span style="font-size:12px;color:var(--mut);font-weight:400">'
        + email + '</span></a>'
    )
    return desktop, mobile


def save_report_data(data):
    report_id = _uuid.uuid4().hex[:12]
    if _HAS_SUPABASE:
        try:
            # Check for previous analysis of same repo
            repo = data.get("repo", "")
            prev_score = None
            prev_critical = None
            prev_row = None
            if repo:
                try:
                    prev = _sb.table("reports").select("score,data").eq("repo", repo).order("created_at", desc=True).limit(1).execute()
                    if prev.data:
                        prev_row = prev.data[0]
                        prev_score = prev_row.get("score", "")
                        prev_data = prev_row.get("data", {})
                        prev_critical = prev_data.get("health", {}).get("critical", None)
                except:
                    pass
            # Add previous score and verifications for same repo
            if prev_score:
                data["prev_score"] = prev_score
                data["prev_critical"] = prev_critical
            # Carry forward verifications from previous analysis of same repo.
            # This used to read `prev` directly, which is unbound whenever the
            # lookup above never ran or threw — a NameError swallowed by the outer
            # except, so carry-forward quietly stopped working and the save looked
            # like it had failed. prev_row is always defined.
            if prev_row is not None:
                prev_verifications = prev_row.get("data", {}).get("verifications", {})
                if prev_verifications:
                    data["verifications"] = prev_verifications
                    print(f"Carried forward {len(prev_verifications)} verifications from previous analysis", flush=True)
            row = {
                "id": report_id,
                "repo": repo,
                "data": data,
                "input_method": data.get("input_method", "github"),
                "score": data.get("health", {}).get("score", "")
            }
            # Attach the report to a signed-in account, so paid users can find it
            # again. Only for signed-in users, which today is nobody — an anonymous
            # free analysis inserts exactly the same row it always did.
            _uid = _current_uid()
            if _uid:
                try:
                    _sb.table("reports").insert(dict(row, user_id=_uid)).execute()
                    return report_id
                except Exception as _link_err:
                    # Most likely the user_id column has not been added yet. Saving
                    # the report matters more than linking it, so fall through.
                    print(f"Report save with user_id failed, saving unlinked: {_link_err}", flush=True)
            _sb.table("reports").insert(row).execute()
            return report_id
        except Exception as e:
            print(f"Supabase save failed: {e}")
    # Fallback to memory
    _reports[report_id] = {"data": data, "saved_at": time.time()}
    expired = [k for k,v in _reports.items() if time.time()-v["saved_at"] > REPORT_TTL]
    for k in expired: del _reports[k]
    return report_id

def get_report_data(report_id):
    if _HAS_SUPABASE:
        try:
            result = _sb.table("reports").select("data").eq("id", report_id).execute()
            if result.data:
                return result.data[0]["data"]
        except Exception as e:
            print(f"Supabase get failed: {e}")
    # Fallback to memory
    entry = _reports.get(report_id)
    if entry and time.time() - entry["saved_at"] < REPORT_TTL:
        return entry["data"]
    return None

# ── Rate limiting ──────────────────────────────────────────────────────────────
_rate_limit = {}

def check_rate_limit(ip):
    now = time.time()
    hits = [t for t in _rate_limit.get(ip, []) if now - t < 3600]
    if len(hits) >= 10:
        _rate_limit[ip] = hits
        return False, int(3600 - (now - min(hits)))
    hits.append(now)
    _rate_limit[ip] = hits
    # Drop addresses with nothing left in the window, otherwise every visitor we
    # have ever had stays in this dict for the life of the process.
    if len(_rate_limit) > 5000:
        for _k in [k for k, v in list(_rate_limit.items()) if not v]:
            _rate_limit.pop(_k, None)
    return True, 0

def get_ip():
    """The caller's real address, from a header the caller cannot forge.

    X-Forwarded-For is supplied by the client and only appended to by each proxy
    in turn, so its FIRST entry is whatever the visitor typed there. Reading that
    entry meant anyone could send a made-up value and appear as a brand new person
    on every request — which made the rate limit above decorative, and every
    analysis it should have blocked costs real Anthropic credits.

    CF-Connecting-IP is set by Cloudflare itself and overwrites anything the
    visitor supplied, so it is the one value here that cannot be spoofed.
    """
    cf = request.headers.get("CF-Connecting-IP", "").strip()
    if cf:
        return cf
    real = request.headers.get("X-Real-IP", "").strip()
    if real:
        return real
    # Last resort. Take the LAST entry, not the first: entries are appended by
    # each hop, so the tail is the part added by infrastructure we control and
    # the head is the part the client made up.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.remote_addr or "unknown"

# ── The paid path ──────────────────────────────────────────────────────────────
# Registered here rather than at the bottom because it needs get_ip and
# get_report_data, which are defined above. It adds routes only — /deep-scan,
# /checkout, /stripe-webhook, /login, /account and friends. Nothing it registers
# is reachable from the free flow, and PAYWALL_ENABLED gates whether anything is
# actually for sale.
if _HAS_PAYWALL:
    try:
        paywall.init(app, sb=_sb, get_ip=get_ip, get_report_data=get_report_data)
        print("✓ Paid path registered"
              + ("" if billing.PAYWALL_ENABLED else " (paywall OFF — nothing for sale)"),
              flush=True)
    except Exception as _bp_err:
        _HAS_PAYWALL = False
        print(f"⚠️  Paid path failed to register: {_bp_err}", flush=True)

# ── File readers ───────────────────────────────────────────────────────────────
PRIORITY_FILES = [
    # Dependency manifests — ALWAYS read first
    "package.json","requirements.txt","pyproject.toml","Gemfile","go.mod","cargo.toml",
    # Environment and config
    ".env.example",".env.local","supabase/config.toml","config.toml","config.yaml","config.json",
    # Auth — all major patterns
    "src/auth.ts","src/auth.js","auth.py","middleware/auth.ts","lib/auth.ts",
    "src/lib/auth.ts","app/auth.ts","server/auth.ts","src/server/auth.ts",
    "middleware.ts","middleware.js",  # NextAuth, Clerk
    "src/middleware.ts",
    # Database schemas and clients
    "prisma/schema.prisma","drizzle.config.ts","schema.ts","src/db/schema.ts",
    "lib/db.ts","lib/database.ts","database.py","src/lib/db.ts",
    "src/integrations/supabase/client.ts","src/lib/supabase.ts",
    "models.py","src/models","db/schema.rb",
    # Frontend HTML entry points — scanned for hardcoded secrets in <script> tags
    "index.html","public/index.html","dist/index.html","src/index.html",
    # Main app entry points
    "app.py","main.py","server.js","server.ts","index.js","index.ts",
    "src/app/layout.tsx","src/app/page.tsx",  # Next.js app router
    "pages/_app.tsx","pages/_app.js",  # Next.js pages router
    "src/main.tsx","src/App.tsx","src/App.jsx",
    # Routes and API handlers
    "src/router.tsx","src/routes.tsx","routes.py",
    "src/app/api","app/api/auth",  # Next.js API routes
    # Build and deployment
    "vite.config.ts","next.config.js","next.config.ts","nuxt.config.ts",
    "Procfile","Dockerfile",".gitignore",
]

# Security-relevant keywords for scoring additional files
SECURITY_KEYWORDS = [
    'auth','login','session','token','jwt','password','secret','key','oauth',
    'database','db','model','schema','migration','query',
    'route','endpoint','api','handler','middleware','guard',
    'config','env','setting','permission','role','admin',
    'upload','storage','bucket','s3','blob',
    'payment','stripe','billing','subscription',
    'email','smtp','webhook','cron',
]

def smart_file_selection(files, max_files=25):
    """Intelligently select the most security-relevant files from a repo."""
    all_paths = list(files.keys())

    # Build a set of priority filenames for O(1) lookup
    priority_names = set()
    priority_suffixes = []
    for pf in PRIORITY_FILES:
        priority_names.add(pf)
        priority_names.add(pf.split('/')[-1])
        priority_suffixes.append(pf)

    selected = []
    selected_set = set()

    # Step 1 — Priority files first (single pass)
    for path in all_paths:
        fname = path.split('/')[-1]
        if fname in priority_names or path in priority_names:
            if path not in selected_set:
                selected.append(path)
                selected_set.add(path)
        if len(selected) >= max_files:
            break

    # Step 2 — Score remaining files (only if needed)
    if len(selected) < max_files:
        remaining = [p for p in all_paths if p not in selected_set]

        def security_score(filepath):
            name = filepath.lower()
            score = 0
            # Quick keyword check
            for kw in SECURITY_KEYWORDS:
                if kw in name:
                    score += 2
                    break  # One match is enough to boost
            if any(d in name for d in ['/api/', '/auth/', '/db/', '/lib/', '/middleware/']):
                score += 3
            if any(d in name for d in ['.test.', '.spec.', '/test/', '/tests/', '/assets/', '/public/', 'node_modules']):
                score -= 10
            if name.endswith(('.ts', '.tsx', '.py', '.go')):
                score += 1
            return score

        # Only sort what we need
        needed = max_files - len(selected)
        if len(remaining) > needed * 3:
            # Sample top candidates without full sort for large repos
            scored = [(security_score(p), p) for p in remaining]
            scored.sort(reverse=True)
            selected.extend([p for _, p in scored[:needed]])
        else:
            scored = sorted(remaining, key=security_score, reverse=True)
            selected.extend(scored[:needed])

    return selected[:max_files]
KEYWORDS = ["auth","login","database","db","schema","route","api","config","secret","supabase","middleware"]
MAX_FILE_CHARS = 120000
MAX_FILES = 25


def categorise_files(paths):
    """Group repo files into plain-English categories by filename/path only.
    Pure string matching — no AI, no cost. Returns ordered list of
    {key, count} for the 'What your app is made of' summary."""
    buckets = {"data": 0, "config": 0, "libs": 0, "visual": 0, "other": 0}
    for p in paths:
        low = p.lower()
        name = low.split("/")[-1]
        # Building blocks — vendored / generated / dependency stuff
        if any(d in low for d in ["node_modules/", "/vendor/", "/dist/", "/build/",
                                  "components/ui/", "/.next/", "package-lock", "yarn.lock",
                                  "pnpm-lock"]):
            buckets["libs"] += 1
        # Data & logins — the security-relevant parts
        elif any(k in low for k in ["auth", "login", "session", "supabase", "database",
                                    "/db/", "schema", "prisma", "migration", "/api/",
                                    "route", "endpoint", "server", "middleware", "webhook",
                                    "payment", "stripe", "/models", "password", "token"]):
            buckets["data"] += 1
        # Settings & config
        elif any(k in low for k in [".env", "config", ".json", ".toml", ".yaml", ".yml",
                                    "vite.", "tsconfig", "tailwind.", "dockerfile",
                                    ".gitignore", "eslint", "postcss"]):
            buckets["config"] += 1
        # Visual & pages — the parts users see
        elif name.endswith((".tsx", ".jsx", ".vue", ".svelte", ".html", ".css", ".scss")) \
                or any(d in low for d in ["/pages/", "/views/", "/screens/", "/components/",
                                         "/layouts/", "/styles/", "/assets/", "/public/"]):
            buckets["visual"] += 1
        else:
            buckets["other"] += 1
    order = ["visual", "data", "config", "libs", "other"]
    return [{"key": k, "count": buckets[k]} for k in order if buckets[k] > 0]
# A URL scan only sees what the site serves to a browser (built/minified output),
# never source. When it returns this few files, a full layer analysis is wasted work
# and would grade from near-nothing — so we return an honest, ungraded preview instead.
THIN_URL_FILES = 3

def grade_from_counts(critical, warnings):
    """Derive the letter grade from actual finding counts.
    Rubric: A=0 critical+0 warnings, B=0 critical+1-3 warnings,
    C=1-2 critical or 4+ warnings, D=3-5 critical, F=6+ critical."""
    if critical >= 6:
        return "F"
    if critical >= 3:
        return "D"
    if critical >= 1:
        return "C"
    if warnings >= 4:
        return "C"
    if warnings >= 1:
        return "B"
    return "A"

def verdict_from_score(score):
    """Derive the launch-readiness verdict from the computed score, so it can never
    contradict the grade. Returns (label, color, reason). Mirrors the live app.js view."""
    m = {
        "A": ("Production Ready", "#1D9E75", "No critical or warning findings — keep dependencies current as you add features."),
        "B": ("Safe to Launch",   "#1D9E75", "The realistic target for AI-built apps. See the score guide for how to reach A."),
        "C": ("Needs Work",       "#EF9F27", "Address the critical findings below, then re-run to update the score."),
        "D": ("Not Ready",        "#E24B4A", "Fix the critical findings below before launching with real users."),
        "F": ("Not Ready",        "#A32D2D", "Several critical findings — fix these before launching with real users."),
    }
    return m.get(score, m["C"])

def fetch_github(repo_url):
    clean = repo_url.replace("https://","").replace("http://","").strip("/")
    parts = clean.split("/")
    for blocked in ["gitlab.com","bitbucket.org","dev.azure.com"]:
        if blocked in parts[0]:
            raise ValueError(f"{blocked.split('.')[0].title()} support coming soon. Use ZIP upload instead.")
    owner = parts[1] if parts[0]=="github.com" else parts[0]
    repo  = (parts[2] if parts[0]=="github.com" else parts[1]).replace(".git","")
    # owner and repo are interpolated straight into an API URL below, so make sure
    # they actually look like GitHub names and cannot carry path segments.
    import re as _re_gh
    if not _re_gh.fullmatch(r"[A-Za-z0-9._-]{1,100}", owner) or \
       not _re_gh.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo):
        raise ValueError("That does not look like a valid GitHub repository URL.")
    base  = f"https://api.github.com/repos/{owner}/{repo}"
    hdrs  = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN: hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    tr = requests.get(f"{base}/git/trees/HEAD?recursive=1", headers=hdrs, timeout=15)
    if tr.status_code == 404: raise ValueError("Repo not found or private. Make it public or use ZIP upload.")
    if tr.status_code == 403: raise ValueError("GitHub rate limit hit. Add a GITHUB_TOKEN to .env.")
    tr.raise_for_status()
    all_files = [i["path"] for i in tr.json().get("tree",[]) if i["type"]=="blob"]

    def fetch_file(path):
        try:
            r = requests.get(f"{base}/contents/{path}", headers=hdrs, timeout=25)
            if r.status_code != 200: return None
            d = r.json()
            if isinstance(d, list): return None
            if d.get("encoding") == "base64":
                return base64.b64decode(d["content"]).decode("utf-8","replace")[:MAX_FILE_CHARS]
            return None
        except: return None

    files = {}
    # Use smart file selection — security-scored prioritisation
    selected_paths = smart_file_selection(
        {p: True for p in all_files},
        max_files=MAX_FILES
    )

    # Ensure manifests are always first — swap in if missing
    for manifest in ['package.json', 'requirements.txt', 'pyproject.toml', 'go.mod']:
        if manifest in all_files and manifest not in selected_paths:
            # Replace last item to stay within MAX_FILES
            if len(selected_paths) >= MAX_FILES:
                selected_paths[-1] = manifest
            else:
                selected_paths.insert(0, manifest)

    # Fetch selected files — hard cap at MAX_FILES
    for path in selected_paths[:MAX_FILES]:
        if path in all_files:
            c = fetch_file(path)
            if c: files[path] = c

    return files, all_files, f"{owner}/{repo}"

# Folders to skip in ZIP analysis
SKIP_FOLDERS = {
    'node_modules', '.git', 'dist', 'build', '__pycache__',
    '.next', '.nuxt', 'vendor', 'venv', '.venv', 'env',
    'coverage', '.cache', 'tmp', 'temp', 'logs', '.DS_Store'
}

def fetch_zip(zip_bytes, filename):
    project_name = filename.replace(".zip","")
    files = {}
    with zipfile.ZipFile(zip_bytes) as zf:
        all_names = zf.namelist()
        prefix = ""
        if all_names and "/" in all_names[0]:
            candidate = all_names[0].split("/")[0] + "/"
            if all(n.startswith(candidate) for n in all_names[:5]): prefix = candidate
        def strip(p): return p[len(prefix):] if p.startswith(prefix) else p
        # Filter out junk folders and binary files
        SKIP_EXTENSIONS = {
            '.png','.jpg','.jpeg','.gif','.ico','.svg','.woff','.woff2',
            '.ttf','.eot','.mp4','.mp3','.wav','.pdf','.zip','.tar',
            '.gz','.map','.lock','.min.js','.min.css'
        }
        filtered_names = [
            n for n in all_names
            if not any(part in SKIP_FOLDERS for part in n.split('/'))
            and not n.endswith('/')
            and not any(n.endswith(ext) for ext in SKIP_EXTENSIONS)
            and not n.startswith('.')
        ]
        # Prioritise important files
        PRIORITY_PATTERNS = [
            'auth','login','database','db','schema','config',
            'env','api','route','server','app','main','index',
            'package.json','requirements.txt','supabase'
        ]
        def priority_score(name):
            name_lower = name.lower()
            for i, pat in enumerate(PRIORITY_PATTERNS):
                if pat in name_lower:
                    return i
            return len(PRIORITY_PATTERNS)

        filtered_names.sort(key=priority_score)
        # Limit to 50 most relevant files
        filtered_names = filtered_names[:50]
        name_map = {strip(n): n for n in filtered_names}
        def read_zip(rel):
            if rel not in name_map: return None
            try:
                info = zf.getinfo(name_map[rel])
                # Skip files larger than 100KB uncompressed
                if info.file_size > 100000: return None
                return zf.read(name_map[rel]).decode("utf-8","replace")[:MAX_FILE_CHARS]
            except: return None
        for p in PRIORITY_FILES:
            if p in name_map:
                c = read_zip(p)
                if c: files[p] = c
        for rel in name_map:
            if len(files) >= MAX_FILES: break
            if rel in files: continue
            fname = rel.lower().split("/")[-1]
            for ext in [".ts",".js",".py",".json"]: fname = fname.replace(ext,"")
            if any(k in fname for k in KEYWORDS):
                c = read_zip(rel)
                if c: files[rel] = c
    return files, list(name_map.keys()), project_name

def fetch_url(live_url):
    from urllib.parse import urlparse
    parsed = urlparse(live_url)
    # Full SSRF check: scheme, port, DNS resolution, and EVERY address the
    # hostname resolves to. See verilay_url_guard.py for what this closes.
    try:
        validate_url(live_url)
    except BlockedURL as e:
        raise ValueError(str(e))
    _headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,*/*", "Accept-Language": "en-US,en;q=0.5"}
    try:
        r = safe_get(live_url, timeout=25, headers=_headers)
    except requests.exceptions.SSLError:
        try:
            # Retry without SSL verification for sites with certificate issues
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = safe_get(live_url, timeout=25, headers=_headers, verify=False)
        except Exception as ssl_e:
            raise ValueError(f"SSL certificate error — this website has an invalid or untrusted certificate. This is itself a security finding. Error: {str(ssl_e)[:100]}")
    except requests.exceptions.ConnectionError as ce:
        raise ValueError(f"Could not connect to this URL. The site may be down or blocking automated access. Try the GitHub URL instead.")
    except requests.exceptions.Timeout:
        raise ValueError("The website took too long to respond (25s timeout). It may be slow or blocking automated access. Try the GitHub URL instead.")
    if r.status_code == 403:
        raise ValueError("This website blocked the scan (403 Forbidden) — it has bot protection or firewall rules. Try using the GitHub URL instead if you have access to the source code.")
    elif r.status_code == 401:
        raise ValueError("This website requires authentication (401 Unauthorized). Try using the GitHub URL instead.")
    elif r.status_code == 404:
        raise ValueError("URL not found (404). Please check the URL is correct and try again.")
    elif r.status_code >= 500:
        raise ValueError(f"The website returned a server error ({r.status_code}). It may be down — try again later.")
    r.raise_for_status()
    domain = live_url.split("/")[2]
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    name = domain.replace(".lovable.app","").replace(".replit.app","")
    html_text = r.text[:120000]

    # Capture security-relevant HTTP response headers
    sec_headers = {}
    for h in ["Content-Security-Policy","X-Frame-Options","X-Content-Type-Options",
              "Strict-Transport-Security","Referrer-Policy","Permissions-Policy"]:
        if h.lower() in {k.lower(): v for k, v in r.headers.items()}:
            sec_headers[h] = r.headers.get(h)
    headers_text = "\n".join(f"{k}: {v}" for k, v in sec_headers.items()) or "No security headers detected"

    files = {
        "index.html": html_text,
        "_meta.txt": f"LIVE URL SCAN: {live_url}",
        "_headers.txt": f"HTTP SECURITY HEADERS:\n{headers_text}"
    }

    # Extract and fetch up to 3 JS bundle files referenced in the HTML
    import re as _re
    js_refs = _re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html_text)
    fetched = 0
    for js_src in js_refs:
        if fetched >= 3:
            break
        try:
            js_url = js_src if js_src.startswith("http") else base_url + ("" if js_src.startswith("/") else "/") + js_src
            # These URLs come from the fetched page, not from our user — a hostile
            # page could point its script tags at an internal address. Same checks apply.
            js_r = safe_get(js_url, timeout=10, headers=_headers)
            if js_r.status_code == 200:
                js_name = js_src.split("/")[-1].split("?")[0] or f"bundle_{fetched+1}.js"
                # Only keep first 40000 chars per JS file to stay within token budget
                files[js_name] = js_r.text[:40000]
                fetched += 1
        except Exception:
            pass

    return files, [], name

# ── Claude API ─────────────────────────────────────────────────────────────────
def call_claude(prompt, max_tokens=2500):
    """Call Claude. Uses official SDK with auto-retry if available, raw requests otherwise."""
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY set.")

    # ── Anthropic SDK path (preferred) ────────────────────────────────
    if _HAS_SDK:
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, max_retries=3)
        raw = ""
        # Ensure prompt is a plain string
        prompt_str = str(prompt) if not isinstance(prompt, str) else prompt
        with client.messages.stream(
            model="claude-sonnet-4-5",
            max_tokens=max_tokens,
            temperature=0,
            messages=[{"role": "user", "content": prompt_str}]
        ) as stream:
            for text in stream.text_stream:
                raw += text

    # ── Fallback: raw requests streaming ──────────────────────────────
    else:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-sonnet-4-5",
                "max_tokens": max_tokens,
                "temperature": 0,
                "stream": True,
                "messages": [{"role": "user", "content": prompt}]
            },
            stream=True,
            timeout=90
        )
        if not resp.ok:
            raise ValueError(f"Claude API {resp.status_code}: {resp.text[:300]}")
        raw = ""
        for line in resp.iter_lines():
            if not line: continue
            line = line.decode("utf-8") if isinstance(line, bytes) else line
            if not line.startswith("data: "): continue
            data = line[6:]
            if data.strip() == "[DONE]": break
            try:
                evt = json.loads(data)
                if evt.get("type") == "content_block_delta":
                    delta = evt.get("delta", {})
                    if delta.get("type") == "text_delta":
                        raw += delta.get("text", "")
            except: continue

    # ── Parse JSON response ────────────────────────────────────────────
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"): raw = raw[4:]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        for i in range(len(raw)-1, 0, -1):
            if raw[i] == "}":
                try: return json.loads(raw[:i+1])
                except: continue
        # Log what we got for debugging
        preview = raw[:500] if raw else "(empty)"
        raise ValueError(f"Parse failed. Response preview: {preview}")


def sanitise_for_prompt(content):
    """Strip control characters that break JSON payloads."""
    content = content.replace("\x00", "").replace("\r", "")
    return "".join(c for c in content if ord(c) >= 32 or c in "\n\t")


# ════════════════════════════════════════════════════════════════════
# ASK VERILAY — Stage 1 (anonymous, IP-rate-limited plain-English Q&A)
# ════════════════════════════════════════════════════════════════════

ASK_VERILAY_SYSTEM = (
    "You are Ask Verilay, a friendly assistant that helps non-developers who have "
    "built apps using AI tools like Lovable, Bolt, Replit, v0, and Cursor.\n\n"
    "WHO YOU ARE TALKING TO: The person is almost certainly NOT a developer. They built "
    "their app by describing what they wanted to an AI tool. They may not know technical "
    "terms and are often anxious about whether their app is safe, working, or ready to "
    "launch. Treat every question as coming from a smart person who simply hasn't learned "
    "the jargon yet.\n\n"
    "YOUR VOICE: Plain English, no unexplained jargon (if you must use a technical term, "
    "define it in everyday words in the same sentence). Warm, encouraging, calm. Never "
    "condescending, never alarmist. Use a short concrete analogy when it helps. Be concise: "
    "lead with the direct answer, then the steps. When the answer is a process, give clear "
    "numbered steps a non-developer can follow.\n\n"
    "WHAT YOU HELP WITH: Building, fixing, understanding, securing, and launching apps made "
    "with AI tools. If a question is clearly OUTSIDE this scope (taxes, legal, medical, "
    "general life questions, writing their marketing copy), gently say it's outside what you "
    "help with and point them to a more suitable resource. Do not answer out-of-scope "
    "questions even if you could.\n\n"
    "MOST IMPORTANT RULE — BE HONEST ABOUT WHAT YOU CAN'T SEE: You CANNOT see the person's "
    "actual app, code, or account. You only have their question. For GENERAL 'how do I / what "
    "is / why does' questions, answer fully and confidently with clear steps. For questions "
    "about THEIR SPECIFIC app ('why is MY app slow?', 'is MY setup secure?'), do NOT guess and "
    "present it as fact — give the general answer clearly labelled as general, and tell them how "
    "to find out for their specific case (run a Verilay scan, or paste a question into their AI "
    "builder). Never claim something about their app is secure/safe/broken when you haven't seen "
    "it.\n\n"
    "SAFETY: If unsure, say so plainly rather than inventing an answer — a confident wrong answer "
    "is worse than 'I'm not certain, but here's how to find out reliably.' Don't help with anything "
    "designed to harm or break into systems. Always end leaving the person feeling capable, not "
    "overwhelmed."
)

ASK_RATE_LIMIT = 3          # free questions allowed per window
ASK_RATE_WINDOW_HOURS = 1   # window length


def _client_ip():
    """Real client IP for the Ask Verilay limiter.

    Delegates to get_ip() so there is exactly one implementation. There used to
    be two, and they had drifted: this one preferred CF-Connecting-IP correctly
    while get_ip() trusted the spoofable first entry of X-Forwarded-For.
    """
    return get_ip()


def ask_rate_check(ip):
    """Per-IP hourly limit via Supabase. Returns (allowed: bool, remaining: int).
    Fails OPEN (allows) if Supabase is unavailable — see note to maintainer."""
    if not _HAS_SUPABASE:
        return True, ASK_RATE_LIMIT  # no store available → don't block users
    bucket = datetime.utcnow().strftime("%Y-%m-%dT%H")  # one bucket per hour (UTC)
    key = f"{ip}|{bucket}"
    try:
        res = _sb.table("ask_usage").select("count").eq("id", key).execute()
        rows = res.data or []
        used = rows[0]["count"] if rows else 0
        if used >= ASK_RATE_LIMIT:
            return False, 0
        if rows:
            _sb.table("ask_usage").update({"count": used + 1}).eq("id", key).execute()
        else:
            _sb.table("ask_usage").insert({"id": key, "count": 1}).execute()
        return True, max(0, ASK_RATE_LIMIT - (used + 1))
    except Exception:
        return True, ASK_RATE_LIMIT  # store error → fail open rather than break the feature


def ask_claude_call(system, prompt, max_tokens=1500):
    """Returns PLAIN TEXT (no JSON parsing) and supports a system prompt.
    Used by Ask Verilay, which answers in plain English, not structured JSON.
    (Named uniquely to avoid colliding with the existing call_claude_text.)"""
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY set.")
    prompt_str = str(prompt)
    if _HAS_SDK:
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, max_retries=3)
        raw = ""
        with client.messages.stream(
            model="claude-sonnet-4-5",
            max_tokens=max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": prompt_str}]
        ) as stream:
            for text in stream.text_stream:
                raw += text
        return raw.strip()
    # raw requests fallback
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": max_tokens,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": prompt_str}]
        },
        timeout=90
    )
    if not resp.ok:
        raise ValueError(f"Claude API {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    parts = data.get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


@app.route("/ask", methods=["POST"])
def ask_verilay():
    try:
        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify({"ok": False, "error": "Please type a question."}), 400
        if len(question) > 1000:
            question = question[:1000]

        ip = _client_ip()
        allowed, remaining = ask_rate_check(ip)
        if not allowed:
            return jsonify({
                "ok": False,
                "limit_reached": True,
                "error": f"You've reached the free limit of {ASK_RATE_LIMIT} questions per hour. "
                         f"More is coming soon. In the meantime, you can run a free Verilay scan of "
                         f"your app, or check back in a little while."
            }), 429

        answer = ask_claude_call(ASK_VERILAY_SYSTEM, question, max_tokens=1500)
        return jsonify({"ok": True, "answer": answer, "remaining": remaining})
    except Exception:
        return jsonify({"ok": False, "error": "Something went wrong answering that. Please try again."}), 500


ASK_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ask Verilay</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;margin:0;font-size:15px;line-height:1.6}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.25rem 7rem;min-height:100vh}
.top{margin-bottom:1.25rem}
.top h1{font-size:22px;font-weight:700;margin:0 0 .35rem}
.top p{font-size:13px;color:#6b6966;margin:0}
.msgs{display:flex;flex-direction:column;gap:.85rem}
.m{padding:.8rem 1rem;border-radius:12px;max-width:90%;white-space:pre-wrap;word-wrap:break-word}
.m.you{align-self:flex-end;background:#1a1917;color:#fff;border-bottom-right-radius:3px}
.m.v{align-self:flex-start;background:#fff;border:0.5px solid #e8e6e0;border-bottom-left-radius:3px}
.m.note{align-self:center;background:#fdf6e3;border:0.5px solid #f0e0b0;color:#7a6a30;font-size:13px;text-align:center;max-width:100%}
.m.v{white-space:normal}
.m.v h3{font-size:15px;font-weight:700;color:#0B5E57;margin:.9em 0 .3em;line-height:1.35}
.m.v h4{font-size:14px;font-weight:700;color:#0B5E57;margin:.7em 0 .25em}
.m.v p{margin:.5em 0}
.m.v p:first-child{margin-top:0}
.m.v ul,.m.v ol{margin:.4em 0;padding-left:1.3em}
.m.v li{margin:.2em 0}
.m.v strong{font-weight:700;color:#1a1917}
.m.v hr{border:none;border-top:0.5px solid #e8e6e0;margin:.9em 0}
.hint{font-size:12px;color:#9a9894;margin:.4rem 2px 0}
.bar{position:fixed;bottom:0;left:0;right:0;background:#f8f8f7;border-top:0.5px solid #e8e6e0;padding:.75rem 1.25rem}
.bar .inner{max-width:680px;margin:0 auto;display:flex;gap:.5rem;align-items:flex-end}
#q{flex:1;border:0.5px solid #d8d6d0;border-radius:10px;padding:.7rem .85rem;font-size:15px;font-family:inherit;resize:none;max-height:140px;background:#fff;color:#1a1917}
#q:focus{outline:none;border-color:#1a1917}
#send{background:#1a1917;color:#fff;border:none;border-radius:10px;padding:.7rem 1.1rem;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap}
#send:disabled{opacity:.45;cursor:default}
.dots span{display:inline-block;width:6px;height:6px;border-radius:50%;background:#b0aeaa;margin:0 1px;animation:b 1.2s infinite}
.dots span:nth-child(2){animation-delay:.2s}.dots span:nth-child(3){animation-delay:.4s}
@keyframes b{0%,60%,100%{opacity:.3}30%{opacity:1}}
</style></head><body>
<div class="wrap">
  <a href="/" onclick="window.close();" style="display:inline-block;font-size:13px;color:#6b6966;text-decoration:none;margin-bottom:1rem">&#10005; Close</a>
  <div class="top">
    <h1>Ask Verilay</h1>
    <p>Plain-English answers about apps built with AI tools &mdash; building, fixing, securing, launching. Free, no jargon. I can't see your specific app, so I'll be honest about what's general advice vs. what needs checking.</p>
  </div>
  <div class="msgs" id="msgs">
    <div class="m v">Hi! Ask me anything about your AI-built app &mdash; like &ldquo;How do I back up my code to GitHub?&rdquo; or &ldquo;How do I add payments?&rdquo;</div>
  </div>
  <div class="hint">Free: 3 questions per hour.</div>
</div>
<div class="bar"><div class="inner">
  <textarea id="q" rows="1" placeholder="Type your question..." maxlength="1000"></textarea>
  <button id="send" onclick="ask()">Ask</button>
</div></div>
<script>
var msgs=document.getElementById('msgs'),q=document.getElementById('q'),send=document.getElementById('send'),busy=false;
q.addEventListener('input',function(){q.style.height='auto';q.style.height=Math.min(q.scrollHeight,140)+'px';});
q.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();ask();}});
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function inl(s){return s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');}
function md(t){
  var ls=esc(t).split('\n'),out=[],lt=null;
  function cl(){if(lt){out.push('</'+lt+'>');lt=null;}}
  function op(type){if(lt!==type){cl();out.push('<'+type+'>');lt=type;}}
  for(var i=0;i<ls.length;i++){
    var l=ls[i];
    if(/^###\s+/.test(l)){cl();out.push('<h4>'+inl(l.replace(/^###\s+/,''))+'</h4>');}
    else if(/^##\s+/.test(l)){cl();out.push('<h3>'+inl(l.replace(/^##\s+/,''))+'</h3>');}
    else if(/^#\s+/.test(l)){cl();out.push('<h3>'+inl(l.replace(/^#\s+/,''))+'</h3>');}
    else if(/^---+\s*$/.test(l)){cl();out.push('<hr>');}
    else if(/^\s*[-*]\s+/.test(l)){op('ul');out.push('<li>'+inl(l.replace(/^\s*[-*]\s+/,''))+'</li>');}
    else if(/^\s*\d+\.\s+/.test(l)){op('ol');out.push('<li>'+inl(l.replace(/^\s*\d+\.\s+/,''))+'</li>');}
    else if(l.trim()===''){cl();}
    else{cl();out.push('<p>'+inl(l)+'</p>');}
  }
  cl();
  return out.join('');
}
function add(cls,text,isMd){var d=document.createElement('div');d.className='m '+cls;if(isMd){d.innerHTML=md(text);}else{d.textContent=text;}msgs.appendChild(d);d.scrollIntoView({behavior:'smooth',block:'end'});return d;}
function ask(){
  if(busy)return;
  var text=q.value.trim();
  if(!text)return;
  add('you',text);
  q.value='';q.style.height='auto';
  busy=true;send.disabled=true;
  var load=document.createElement('div');load.className='m v';load.innerHTML='<span class="dots"><span></span><span></span><span></span></span>';msgs.appendChild(load);load.scrollIntoView({behavior:'smooth',block:'end'});
  fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:text})})
    .then(function(r){return r.json().then(function(j){return {status:r.status,j:j};});})
    .then(function(res){
      load.remove();
      if(res.j.ok){add('v',res.j.answer,true);}
      else if(res.j.limit_reached){add('note',res.j.error);}
      else{add('note',res.j.error||'Something went wrong. Please try again.');}
    })
    .catch(function(){load.remove();add('note','Could not reach the server. Please try again.');})
    .finally(function(){busy=false;send.disabled=false;q.focus();});
}
(function(){
  var m=location.search.match(/[?&]q=([^&]+)/);
  if(m){q.value=decodeURIComponent(m[1].replace(/\+/g,' '));ask();}
})();
</script>
</body></html>"""


@app.route("/ask-verilay")
def ask_verilay_page():
    return ASK_PAGE_HTML


def files_for(files, keys, max_total=250000):
    """Build file text block from selected keys, capped at max_total chars."""
    out = ""
    total = 0
    for k in keys:
        if k in files and total < max_total:
            content = sanitise_for_prompt(files[k])
            chunk = "\n\n=== " + k + " ===\n" + content
            out += chunk
            total += len(chunk)
    return out


def call_claude_text(prompt, max_tokens=800):
    """Call Claude expecting plain text key:value response."""
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY set.")
    if _HAS_SDK:
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, max_retries=3)
        raw = ""
        with client.messages.stream(
            model="claude-sonnet-4-5",
            max_tokens=max_tokens,
            temperature=0,
            messages=[{"role": "user", "content": str(prompt)}]
        ) as stream:
            for text in stream.text_stream:
                raw += text
        return raw.strip()
    else:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
            json={"model":"claude-sonnet-4-5","max_tokens":max_tokens,"temperature":0,"stream":True,
                  "messages":[{"role":"user","content":str(prompt)}]},
            stream=True, timeout=90
        )
        if not resp.ok:
            raise ValueError(f"Claude API {resp.status_code}: {resp.text[:200]}")
        raw = ""
        for line in resp.iter_lines():
            if not line: continue
            line = line.decode("utf-8") if isinstance(line, bytes) else line
            if not line.startswith("data: "): continue
            data = line[6:]
            if data.strip() == "[DONE]": break
            try:
                evt = json.loads(data)
                if evt.get("type") == "content_block_delta":
                    delta = evt.get("delta", {})
                    if delta.get("type") == "text_delta":
                        raw += delta.get("text", "")
            except: continue
        return raw.strip()


_LAYER_DEFAULTS = {
    "Auth": "Auth is the login system — it checks who you are before letting you into the app, like a bouncer at the door.",
    "Config": "Config stores your app settings and secret keys — like a locked filing cabinet with all the codes your app needs to run.",
    "Database": "The Database stores everything permanently — user accounts, content, orders. Without it the app forgets everything when you close it.",
    "API": "The API is the messenger between what users see and where data lives — like a waiter taking orders to the kitchen and bringing food back.",
    "Frontend": "The Frontend is everything users see in their browser — buttons, forms, pages. It runs on the user device, not your server.",
    "Libraries": "Libraries are ready-made code packages your app uses instead of building everything from scratch — like buying pre-made ingredients.",
}

def _layer_default(name):
    return _LAYER_DEFAULTS.get(name, f"The {name} layer handles related functionality.")


def parse_flat_response(text, layer_names):
    """Parse flat key:value Claude response into layer structure."""
    kv = {}
    for line in text.strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            kv[key.strip().upper()] = val.strip()

    layers = []
    for name in layer_names:
        p = name.upper().replace(" ", "_").replace("-", "_")
        status = kv.get(f"{p}_STATUS", "passing").lower()
        if status not in ("critical", "warning", "passing"):
            status = "passing"

        findings_expert = []
        findings_learner = []
        for i in range(1, 6):
            title = kv.get(f"{p}_F{i}_TITLE", "")
            if not title or title.lower() in ("finding title", "finding", "next", ""):
                break
            sev = kv.get(f"{p}_F{i}_SEV", "passing").lower()
            if sev not in ("critical", "warning", "passing", "info"):
                sev = "passing"
            findings_expert.append({
                "severity": sev,
                "title": title,
                "detail": kv.get(f"{p}_F{i}_DETAIL", ""),
                "file": kv.get(f"{p}_F{i}_FILE", ""),
                "why_it_matters": kv.get(f"{p}_F{i}_WHY", "")
            })
            findings_learner.append({
                "severity": sev,
                "plain_title": title,
                "plain_detail": kv.get(f"{p}_F{i}_PLAIN", kv.get(f"{p}_F{i}_DETAIL", "")),
                "real_world_impact": kv.get(f"{p}_F{i}_IMPACT", ""),
                "action": kv.get(f"{p}_F{i}_ACTION", "")
            })

        if not findings_expert:
            findings_expert = [{"severity":"passing","title":"No issues found",
                "detail":"Layer appears healthy","file":"","why_it_matters":""}]
            findings_learner = [{"severity":"passing","plain_title":"No issues found",
                "plain_detail":"This layer looks good","real_world_impact":"","action":""}]

        # Build quiz - use defaults if Claude didn't provide one
        q = kv.get(f"{p}_Q", "").strip()
        a = kv.get(f"{p}_A", "").strip()
        qwhy = kv.get(f"{p}_QWHY", "").strip()

        default_questions = {
            "Auth": ("What is the purpose of the Auth layer?",
                     "The Auth layer controls who can access your app and verifies user identity.",
                     "Understanding auth helps you know if your app is protected from unauthorised access."),
            "Config": ("What does the Config layer do?",
                       "The Config layer stores settings and environment variables your app needs to run.",
                       "Misconfigured settings are one of the most common causes of security breaches."),
            "Database": ("What is the Database layer responsible for?",
                         "The Database layer stores and retrieves all your app data persistently.",
                         "Understanding your database layer helps you know if user data is safe."),
            "API": ("What does the API layer do?",
                    "The API layer handles requests between your frontend and backend, defining what actions are possible.",
                    "A well-designed API is the backbone of a secure and reliable app."),
            "Frontend": ("What is the Frontend layer?",
                         "The Frontend layer is everything users see and interact with in their browser.",
                         "The frontend layer affects performance, accessibility and user experience."),
            "Libraries": ("What are Libraries in your app?",
                          "Libraries are pre-built code packages your app uses instead of writing everything from scratch.",
                          "Outdated libraries are the most common source of security vulnerabilities in AI-built apps."),
        }

        if not q or not a:
            dq, da, dw = default_questions.get(name, (
                f"What is the {name} layer responsible for?",
                f"The {name} layer handles a specific aspect of your application's functionality.",
                "Understanding each layer helps you make better decisions about your app."
            ))
            q = q or dq
            a = a or da
            qwhy = qwhy or dw

        layers.append({
            "name": name,
            "status": status,
            "expert": {
                "summary": kv.get(f"{p}_SUMMARY", f"{name} layer analysis."),
                "findings": findings_expert
            },
            "learner": {
                "what_is_it": kv.get(f"{p}_WHAT", _layer_default(name)),
                "analogy": kv.get(f"{p}_ANALOGY", ""),
                "what_it_does_in_your_app": kv.get(f"{p}_DOES", ""),
                "how_it_connects": kv.get(f"{p}_CONNECTS", ""),
                "key_concept": kv.get(f"{p}_CONCEPT", ""),
                "findings_plain": findings_learner
            },
            "quiz": [{"question": q, "answer": a, "why": qwhy}]
        })
    return {"layers": layers}


def analyse_step1(files, tree, repo_name, method):
    # Limit files for ZIP uploads to keep analysis fast
    if method == "zip" and len(files) > 20:
        priority_keys = sorted(files.keys(), key=lambda k: (
            0 if any(p in k.lower() for p in ['auth','login','config','env','database','db','schema']) else
            1 if any(p in k.lower() for p in ['api','route','server','app','main','index']) else
            2
        ))[:20]
        files = {k: files[k] for k in priority_keys}

    tree_str = "\n".join(tree[:60]) if tree else "Not available"
    stack_keys = [k for k in files if any(sf in k for sf in
        ["package.json","requirements","Procfile","vite","tsconfig",".gitignore","Dockerfile"])]
    ftext = files_for(files, stack_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:250000]
    is_surface = method == "url"

    prompt = (
        "Analyse this codebase and respond ONLY with key:value pairs, one per line, no other text.\n\n"
        "Repo: " + repo_name + "\n"
        "File tree:\n" + tree_str + "\n\n"
        "Key files:\n" + ftext + "\n\n"
        "IMPORTANT: Read package.json or requirements.txt first to identify exact libraries. "
        "Determine auth library (nextauth/clerk/auth0/supabase/passport/jwt/lucia/better-auth), "
        "database (prisma/drizzle/mongoose/supabase/sqlalchemy/gorm/typeorm), "
        "and framework (nextjs/express/flask/fastapi/django/hono/nuxt/sveltekit/astro). "
        "Your findings must reflect actual libraries present — never assume patterns not in dependencies.\\n\\n"
        "Use exactly these keys:\n\n"
        "SUMMARY: one sentence what this app does\n"
        "BUILT_WITH: which AI platform built this and why you think so\n"
        "DEPTH: " + ("surface" if is_surface else "full") + "\n"
        "VERDICT: ready|needs_work|not_ready\n"
        "CONFIDENCE: high|medium|low\n"
        "REASON: one sentence verdict\n"
        "CRITICAL: number of critical issues\n"
        "WARNINGS: number of warnings\n"
        "PASSING: number of passing checks\n"
        "SCORE: A=0 critical+0 warnings, B=0 critical+1-3 warnings, C=1-2 critical or 4+ warnings, D=3-5 critical, F=6+ critical\\n"
        "STACK_1_NAME: framework or library name\n"
        "STACK_1_VERSION: version or empty\n"
        "STACK_1_CAT: frontend|backend|database|auth|styling|build|testing|other\n"
        "STACK_1_DESC: one sentence what it does\n"
        "STACK_2_NAME: next item\n"
        "STACK_2_VERSION: version\n"
        "STACK_2_CAT: category\n"
        "STACK_2_DESC: description\n"
        "STACK_3_NAME: next\n"
        "STACK_3_VERSION: version\n"
        "STACK_3_CAT: category\n"
        "STACK_3_DESC: description\n"
        "STACK_4_NAME: next\n"
        "STACK_4_VERSION: version\n"
        "STACK_4_CAT: category\n"
        "STACK_4_DESC: description\n"
        "STACK_5_NAME: next\n"
        "STACK_5_VERSION: version\n"
        "STACK_5_CAT: category\n"
        "STACK_5_DESC: description\n"
        "STACK_6_NAME: next or empty\n"
        "STACK_6_VERSION: version\n"
        "STACK_6_CAT: category\n"
        "STACK_6_DESC: description\n"
        "STATIC_RECOMMENDATION: yes|no|partial — could this app be simplified to a static site?\n"
        "STATIC_REASON: one sentence — why or why not it could be static (only if STATIC_RECOMMENDATION is yes or partial)\n"
        "\nBe honest. A score means truly production-ready. Most AI-built apps score B or C.\n"
        "List all libraries/frameworks found. Leave STACK_N fields empty if fewer than N items.\n"
        "IMPORTANT: If input method is 'url' (surface scan), do NOT flag environment variable patterns as security issues "
        "since you cannot inspect server-side configuration from a live URL. Only flag issues visible in the HTML/JS.\n"
        "For URL scans: present findings as 'potential issue — verify manually' not confirmed vulnerabilities. "
        "Never mark something as critical from a URL scan unless it is clearly visible in the HTML/JS (e.g. actual API key in source). "
        "Do NOT flag missing auth or missing backend config from a URL scan — those cannot be assessed without seeing the code.\n"
        "SECRET DETECTION IN URL SCANS: actively scan index.html and any JS bundle files for hardcoded API keys or secrets. "
        "Look for patterns like sk-ant-, sk-proj-, OPENAI_API_KEY=, AIza, Bearer tokens, Stripe sk_, Twilio AC, and any string matching [A-Za-z0-9_]{20,} assigned to a variable named key, secret, token, apiKey, or api_key inside <script> tags or JS files. "
        "If found, flag as CRITICAL with the exact variable name and partial value (first 6 chars only). "
        "SECURITY HEADERS: a _headers.txt file is included with the HTTP response headers. Flag missing Content-Security-Policy or Strict-Transport-Security as a warning. "
        "If all security headers are absent, flag as a warning — 'No security headers detected'.\n"
        "Do NOT flag meta http-equiv cache tags as security issues — real caching is controlled by HTTP response headers not meta tags.\n"
        "AUTH POSTURE HEADERS: If you see @auth-required: false or @public: true in function comments → that function is intentionally public, never flag it. "
        "If you see @auth-method: in-code → auth is validated in the function code, not the gateway — never flag verify_jwt=false for these functions. "
        "If you see a SECURITY.md file → read it to understand the project auth model before flagging any auth issues."
    )

    text = call_claude_text(prompt, max_tokens=700)
    lines = {}
    for line in text.strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            lines[key.strip().upper()] = val.strip()

    # Build stack array
    stack = []
    for i in range(1, 8):
        name = lines.get(f"STACK_{i}_NAME", "").strip()
        if not name or name.lower() in ("next", "next item", "next or empty", "empty"):
            break
        stack.append({
            "name": name,
            "version": lines.get(f"STACK_{i}_VERSION", ""),
            "category": lines.get(f"STACK_{i}_CAT", "other"),
            "plain_english": lines.get(f"STACK_{i}_DESC", "")
        })

    critical = int(lines.get("CRITICAL", "0").split()[0]) if lines.get("CRITICAL", "").split() else 0
    warnings = int(lines.get("WARNINGS", "0").split()[0]) if lines.get("WARNINGS", "").split() else 0
    passing  = int(lines.get("PASSING", "0").split()[0]) if lines.get("PASSING", "").split() else 0

    return {
        "repo": repo_name,
        "input_method": method,
        "analysis_depth": lines.get("DEPTH", "full" if not is_surface else "surface"),
        "summary": lines.get("SUMMARY", ""),
        "built_with": lines.get("BUILT_WITH", ""),
        "prod_ready": {
            "verdict": lines.get("VERDICT", "needs_work"),
            "confidence": lines.get("CONFIDENCE", "medium"),
            "reason": lines.get("REASON", ""),
            "static_recommendation": lines.get("STATIC_RECOMMENDATION", "no"),
            "static_reason": lines.get("STATIC_REASON", "")
        },
        "health": {
            "critical": critical,
            "warnings": warnings,
            "passing": passing,
            "score": lines.get("SCORE", "C")
        },
        "stack": stack,
        "files_read": len(files),
        "generated_at": __import__("datetime").datetime.now().strftime("%d %b %Y %H:%M")
    }


def analyse_step2(files, repo_name, scan_block=""):
    sec_keys = [k for k in files if any(w in k.lower() for w in
        ["auth","login",".env","config","supabase","database","db","schema","prisma","password","token"])][:6]
    ftext = files_for(files, sec_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:250000]

    prompt = (
        "You are Verilay analysing " + repo_name + " for a non-developer who built this app with an AI tool.\n\n"
        + scan_block +
        "WRITING FOR NON-TECHNICAL USERS (applies to ALL plain-English / Learner fields — WHAT, ANALOGY, DOES, CONNECTS, CONCEPT, PLAIN, IMPACT, A):\n"
        "- Assume the reader has NEVER coded and does not know what a database, API, server, or authentication is. Imagine explaining to a plumber, a hairdresser, or a shop owner who built an app to run their small business.\n"
        "- Do NOT assume any baseline. If you use a technical word at all, immediately explain it in everyday terms in the same sentence.\n"
        "- Write a short, warm PARAGRAPH (about 3-5 sentences), NOT one or two clipped lines. Enough to actually teach, but never a wall of text.\n"
        "- Ground every explanation in an everyday, real-life example the reader already understands (a shop, a job diary, a locked door, a filing cabinet, a receptionist taking messages). Prefer examples from ordinary life over anything technical.\n"
        "- For anything risky, give a concrete real-world consequence in plain terms (e.g. 'a stranger could open your customer list and read everyone's home address and phone number', not 'unauthorised data access').\n"
        "- In the DOES/CONNECTS fields, you may name the actual tool found (e.g. Supabase) ONCE, but immediately explain what it is in plain words — never leave a technical name unexplained.\n"
        "- No jargon, no acronyms left undefined. If your explanation would confuse a smart person who has never touched software, rewrite it simpler.\n\n"
        "FILES:\\n" + ftext + "\\n\\n" +
        "PLATFORM AWARENESS — NEVER FLAG these correct patterns:\n"
        "- Supabase anon key in frontend: by design, security from RLS not hiding key\n"
        "- verify_jwt=false in config.toml: fine BY ITSELF (Lovable Cloud default) for public endpoints or functions that verify auth in their own code. EXCEPTION — DO flag as CRITICAL when verify_jwt=false AND the function uses the service-role key AND has no in-code auth/secret check AND performs data-modifying or destructive operations (e.g. a cron-triggered delete/cleanup). That specific combination is a real unauthenticated-access vulnerability, not a platform default\n"
        "- try/catch on Supabase: wrong pattern, use {data,error}\n"
        "- TanStack Query loading states: built in\n"
        "- Replit Auth isAuthenticated/isAdmin/requireAuth: valid OIDC\n"
        "- Firebase Auth onAuthStateChanged/getAuth: valid auth\n"
        "- Passwordless/magic links: valid secure auth\n"
        "- Drizzle ORM TypeScript schemas: type validation handled\n"
        "- Flask @app.route/jsonify/os.getenv(): correct patterns\n"
        "- Gunicorn: production WSGI server, never flag as dev server\n"
        "- NextAuth useSession/getServerSession: valid auth\n"
        "- Clerk clerkMiddleware/useUser: valid auth\n"
        "- Prisma client: ORM handles injection prevention\n"
        "- asyncHandler wrapper: handles async errors correctly\n"
        "- Public tools @auth-required:false or @public:true: intentionally public\n"
        "- Local-only apps with no server: no auth/API/DB findings apply\n"
        "ADVICE: investigate and advise first, never suggest competing libraries.\n\n"
        "SECRET DETECTION: do NOT hunt for secrets yourself. A deterministic scanner has already "
        "checked every file in the repository and its results are in the CONFIRMED SECRET SCAN block "
        "above — that block is authoritative and complete. Report exactly those findings, at the "
        "severity given, explained in plain English. Do not add secret findings that are not listed "
        "there, and do not omit any that are. Note also that import.meta.env.* and process.env.* are "
        "references, not secrets, and are never findings.\n"
        "- EXTERNAL SCRIPTS: if app.js/main.js referenced via <script src=> tag — JS is present externally, NEVER flag as missing. Also if the HTML source shows /static/app.js or any external .js reference, the JavaScript IS fully present.\\n"
        "- URL SCAN TRUNCATION: URL scans only fetch partial HTML — truncated CSS like .ll{{display:gr is normal. NEVER flag truncated URL content as broken or incomplete code.\\n"
        "- AI-POWERED TOOLS: if Anthropic/OpenAI/Gemini API present — AI IS the analysis engine, NEVER flag missing Prism/CodeMirror/AST parsers.\\n"
        "- MINIFIED CODE: truncated or minified CSS/JS in HTML is normal — NEVER flag as incomplete or broken. Minification/bundling is the sign of a CORRECT production build, NOT a problem: NEVER flag it as a security finding, an auth-verification blocker, or a reason the app 'cannot be reviewed'. Do not say minified code 'prevents security review'. At most mention once as informational, and NEVER let minification lower the grade or appear as a warning/critical.\\n\\n"
        "AUTH_F1_TITLE: short finding title\n"
        "AUTH_F1_DETAIL: one sentence technical detail — only flag if genuinely missing\n"
        "AUTH_F1_FILE: filename or empty\n"
        "AUTH_F1_WHY: why this matters to the business\n"
        "AUTH_F1_PLAIN: same finding in plain English a 10-year-old would understand\n"
        "AUTH_F1_IMPACT: specific real-world consequence if not fixed (e.g. a stranger could log in as any user)\n"
        "AUTH_F1_ACTION: exact step to fix this in Lovable or Replit\n"
        "AUTH_WHAT: what the auth layer IS, following the non-technical writing rules above (short warm paragraph, everyday example, no unexplained jargon)\n"
        "AUTH_ANALOGY: a vivid UNIQUE analogy specific to what THIS exact app does. NEVER use generic analogies like bouncer, front door, or receptionist. Instead use something specific to the app domain — e.g. for a construction app use site security guard checking trade licences, for a recipe app use a kitchen pass system, for a legal app use courthouse security. Make it memorable and directly relevant to what users of THIS app would understand\n"
        "AUTH_DOES: what auth specifically does in THIS app — mention actual libraries/services found in the code (Supabase, JWT, sessions etc)\n"
        "AUTH_CONNECTS: explain in plain English how auth connects to other parts — like how the bouncer talks to the guest list (database)\n"
        "AUTH_CONCEPT: the single most important insight a non-developer should take away about auth in this specific app — make it practical\n"
        "AUTH_Q: a quiz question about the specific auth finding — not generic, tied to what was actually found in this app\n"
        "AUTH_A: the answer explained simply — as if explaining to a smart friend who doesn't code\n"
        "AUTH_QWHY: one sentence on why understanding this protects their users and business\n"
        "CONFIG_STATUS: critical|warning|passing\n"
        "CONFIG_SUMMARY: one sentence technical summary\n"
        "CONFIG_F1_SEV: critical|warning|passing\n"
        "CONFIG_F1_TITLE: finding title\n"
        "CONFIG_F1_DETAIL: technical detail\n"
        "CONFIG_F1_FILE: filename\n"
        "CONFIG_F1_WHY: business impact\n"
        "CONFIG_F1_PLAIN: plain English\n"
        "CONFIG_F1_IMPACT: real-world consequence\n"
        "CONFIG_F1_ACTION: fix step\n"
        "CONFIG_WHAT: what config is in plain English\n"
        "CONFIG_ANALOGY: a UNIQUE analogy specific to this app domain. NEVER use filing cabinet or lockbox. Use something relevant — e.g. for a restaurant app use recipe ingredient ratios kept in the chef notebook, for a finance app use the vault combination settings. Make it specific to what THIS app does\n"
        "CONFIG_DOES: what config does in this specific app\n"
        "CONFIG_CONNECTS: how it connects to other layers\n"
        "CONFIG_CONCEPT: most important concept\n"
        "CONFIG_Q: quiz question specific to this finding\n"
        "CONFIG_A: plain English answer\n"
        "CONFIG_QWHY: why it matters\n"
        "DATABASE_STATUS: critical|warning|passing\n"
        "DATABASE_SUMMARY: one sentence technical summary\n"
        "DATABASE_F1_SEV: critical|warning|passing\n"
        "DATABASE_F1_TITLE: finding title\n"
        "DATABASE_F1_DETAIL: technical detail\n"
        "DATABASE_F1_FILE: filename\n"
        "DATABASE_F1_WHY: business impact\n"
        "DATABASE_F1_PLAIN: plain English\n"
        "DATABASE_F1_IMPACT: real-world consequence\n"
        "DATABASE_F1_ACTION: fix step\n"
        "DATABASE_WHAT: what the database is in plain English\n"
        "DATABASE_ANALOGY: a UNIQUE analogy tied to what this app actually stores. NEVER use generic warehouse or storage unit. If it stores documents use a library archive, if it stores orders use a kitchen order ticket system, if it stores properties use a land registry. Match the analogy to the actual data the app handles\n"
        "DATABASE_DOES: what the database stores in this specific app\n"
        "DATABASE_CONNECTS: how it connects to other layers\n"
        "DATABASE_CONCEPT: most important concept\n"
        "DATABASE_Q: quiz question specific to this finding\n"
        "DATABASE_A: plain English answer\n"
        "DATABASE_QWHY: why it matters\n"
    )
    text = call_claude_text(prompt, max_tokens=1200)
    return parse_flat_response(text, ["Auth", "Config", "Database"])


def analyse_step3(files, repo_name, osv_block=""):
    api_keys = [k for k in files if any(w in k.lower() for w in
        ["route","api","app.py","main.py","server","app.tsx","app.jsx","package.json"])][:6]
    if "package.json" in files and "package.json" not in api_keys:
        api_keys.insert(0, "package.json")
    ftext = files_for(files, api_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:250000]

    prompt = (
        "You are Verilay analysing " + repo_name + " for a non-developer who built this with an AI tool.\n\n"
        + osv_block +
        "WRITING FOR NON-TECHNICAL USERS (applies to ALL plain-English / Learner fields — WHAT, ANALOGY, DOES, CONNECTS, CONCEPT, PLAIN, IMPACT, A):\n"
        "- Assume the reader has NEVER coded and does not know what a database, API, server, or authentication is. Imagine explaining to a plumber, a hairdresser, or a shop owner who built an app to run their small business.\n"
        "- Do NOT assume any baseline. If you use a technical word at all, immediately explain it in everyday terms in the same sentence.\n"
        "- Write a short, warm PARAGRAPH (about 3-5 sentences), NOT one or two clipped lines. Enough to actually teach, but never a wall of text.\n"
        "- Ground every explanation in an everyday, real-life example the reader already understands (a shop, a job diary, a locked door, a filing cabinet, a receptionist taking messages). Prefer examples from ordinary life over anything technical.\n"
        "- For anything risky, give a concrete real-world consequence in plain terms (e.g. 'a stranger could open your customer list and read everyone's home address and phone number', not 'unauthorised data access').\n"
        "- In the DOES/CONNECTS fields, you may name the actual tool found (e.g. Supabase) ONCE, but immediately explain what it is in plain words — never leave a technical name unexplained.\n"
        "- No jargon, no acronyms left undefined. If your explanation would confuse a smart person who has never touched software, rewrite it simpler.\n\n"
        "FILES:\n" + ftext + "\n\n" +
        "PLATFORM AWARENESS — NEVER FLAG these correct patterns:\n"
        "- Supabase anon key in frontend: by design, security from RLS not hiding key\n"
        "- verify_jwt=false in config.toml: fine BY ITSELF (Lovable Cloud default) for public endpoints or functions that verify auth in their own code. EXCEPTION — DO flag as CRITICAL when verify_jwt=false AND the function uses the service-role key AND has no in-code auth/secret check AND performs data-modifying or destructive operations (e.g. a cron-triggered delete/cleanup). That specific combination is a real unauthenticated-access vulnerability, not a platform default\n"
        "- try/catch on Supabase: wrong pattern, use {data,error}\n"
        "- TanStack Query loading states: built in\n"
        "- Replit Auth isAuthenticated/isAdmin/requireAuth: valid OIDC\n"
        "- Firebase Auth onAuthStateChanged/getAuth: valid auth\n"
        "- Passwordless/magic links: valid secure auth\n"
        "- Drizzle ORM TypeScript schemas: type validation handled\n"
        "- Flask @app.route/jsonify/os.getenv(): correct patterns\n"
        "- Gunicorn: production WSGI server, never flag as dev server\n"
        "- NextAuth useSession/getServerSession: valid auth\n"
        "- Clerk clerkMiddleware/useUser: valid auth\n"
        "- Prisma client: ORM handles injection prevention\n"
        "- asyncHandler wrapper: handles async errors correctly\n"
        "- Public tools @auth-required:false or @public:true: intentionally public\n"
        "- Local-only apps with no server: no auth/API/DB findings apply\n"
        "ADVICE: investigate and advise first, never suggest competing libraries.\n\n"
        "- EXTERNAL SCRIPTS: if app.js/main.js referenced via <script src=> tag — JS is present externally, NEVER flag as missing. Also if the HTML source shows /static/app.js or any external .js reference, the JavaScript IS fully present.\\n"
        "- URL SCAN TRUNCATION: URL scans only fetch partial HTML — truncated CSS like .ll{{display:gr is normal. NEVER flag truncated URL content as broken or incomplete code.\\n"
        "- AI-POWERED TOOLS: if Anthropic/OpenAI/Gemini API present — AI IS the analysis engine, NEVER flag missing Prism/CodeMirror/AST parsers.\\n"
        "- MINIFIED CODE: truncated or minified CSS/JS in HTML is normal — NEVER flag as incomplete or broken. Minification/bundling is the sign of a CORRECT production build, NOT a problem: NEVER flag it as a security finding, an auth-verification blocker, or a reason the app 'cannot be reviewed'. Do not say minified code 'prevents security review'. At most mention once as informational, and NEVER let minification lower the grade or appear as a warning/critical.\\n\\n"
        "- Only flag something as critical or warning if GENUINELY absent or misconfigured in the actual code\n\n"
        "Respond ONLY with key:value pairs, one per line. Be specific to THIS app, not generic.\n\n"
        "API_STATUS: critical|warning|passing\n"
        "API_SUMMARY: one sentence technical summary\n"
        "API_F1_SEV: critical|warning|passing\n"
        "API_F1_TITLE: finding title\n"
        "API_F1_DETAIL: technical detail\n"
        "API_F1_FILE: filename\n"
        "API_F1_WHY: business impact\n"
        "API_F1_PLAIN: plain English\n"
        "API_F1_IMPACT: real-world consequence\n"
        "API_F1_ACTION: fix step\n"
        "API_WHAT: what the API layer is in plain English (no jargon)\n"
        "API_ANALOGY: a UNIQUE analogy for this specific app. NEVER use waiter/kitchen analogy. Use something tied to the app domain — for a travel app use an airline dispatcher, for a medical app use a hospital triage system, for a construction app use a site foreman relaying instructions\n"
        "API_DOES: what the API specifically does in this app based on the code\n"
        "API_CONNECTS: how API connects to frontend and database\n"
        "API_CONCEPT: most important concept to understand\n"
        "API_Q: quiz question specific to this app findings\n"
        "API_A: plain English answer\n"
        "API_QWHY: why it matters\n"
        "FRONTEND_STATUS: critical|warning|passing\n"
        "FRONTEND_SUMMARY: one sentence technical summary\n"
        "FRONTEND_F1_SEV: critical|warning|passing\n"
        "FRONTEND_F1_TITLE: finding title\n"
        "FRONTEND_F1_DETAIL: technical detail\n"
        "FRONTEND_F1_FILE: filename\n"
        "FRONTEND_F1_WHY: business impact\n"
        "FRONTEND_F1_PLAIN: plain English\n"
        "FRONTEND_F1_IMPACT: real-world consequence\n"
        "FRONTEND_F1_ACTION: fix step\n"
        "FRONTEND_WHAT: what the frontend is in plain English\n"
        "FRONTEND_ANALOGY: a UNIQUE analogy for this app. NEVER use shop window or dashboard. Use something specific — for a document app use the reading room in a library, for a booking app use the customer facing reception desk, for a security scanner use the control panel of a CCTV system\n"
        "FRONTEND_DOES: what the frontend does in this specific app\n"
        "FRONTEND_CONNECTS: how frontend connects to API and auth\n"
        "FRONTEND_CONCEPT: most important concept\n"
        "FRONTEND_Q: quiz question specific to this app\n"
        "FRONTEND_A: plain English answer\n"
        "FRONTEND_QWHY: why it matters\n"
        "DEPENDENCY VULNERABILITIES: do NOT scan for vulnerable dependencies yourself. The "
        "CONFIRMED DEPENDENCY CHECK block above (if present) is authoritative — base "
        "LIBRARIES_STATUS and the first Libraries finding on it exactly as instructed there. If "
        "no such block is present, do not invent dependency vulnerability findings.\n"
        "LIBRARIES_STATUS: critical|warning|passing\n"
        "LIBRARIES_SUMMARY: one sentence technical summary\n"
        "LIBRARIES_F1_SEV: critical|warning|passing\n"
        "LIBRARIES_F1_TITLE: finding title\n"
        "LIBRARIES_F1_DETAIL: technical detail\n"
        "LIBRARIES_F1_FILE: filename\n"
        "LIBRARIES_F1_WHY: business impact\n"
        "LIBRARIES_F1_PLAIN: plain English\n"
        "LIBRARIES_F1_IMPACT: real-world consequence\n"
        "LIBRARIES_F1_ACTION: fix step\n"
        "LIBRARIES_WHAT: what libraries are in plain English\n"
        "LIBRARIES_ANALOGY: a UNIQUE analogy for this app. NEVER use toolbox or pre-made ingredients. Use something domain-specific — for a construction app use specialist subcontractors, for a medical app use specialist consultants, for a food app use ready-made sauce bases from professional suppliers\n"
        "LIBRARIES_DOES: what the key libraries do in this app\n"
        "LIBRARIES_CONNECTS: how libraries connect to other layers\n"
        "LIBRARIES_CONCEPT: most important concept\n"
        "LIBRARIES_Q: quiz question specific to this app\n"
        "LIBRARIES_A: plain English answer\n"
        "LIBRARIES_QWHY: why it matters\n"
    )
    text = call_claude_text(prompt, max_tokens=1200)
    return parse_flat_response(text, ["API", "Frontend", "Libraries"])


def apply_osv_library_fallback(s3, osv_vulns, osv_checked):
    """If OSV genuinely checked dependencies but Claude's Libraries write-up
    is still the generic parse_flat_response boilerplate, replace it with a
    specific, deterministic statement built from the OSV numbers. Cheaper and
    more reliable than hoping the model complies with the teaser instruction
    every single time — and it matters more than cosmetics: without this, a
    real vulnerability could get graded correctly (the floor in analyse_stream
    already handles that) while the narrative still says "No issues found",
    which is exactly the kind of contradiction Decision 2a exists to prevent.
    Never overwrites content Claude actually wrote."""
    if osv_checked == 0:
        return s3
    for layer in s3.get("layers", []):
        if layer.get("name") != "Libraries":
            continue
        findings = layer.get("expert", {}).get("findings", [])
        is_generic = (
            layer.get("expert", {}).get("summary") == "Libraries layer analysis."
            and len(findings) == 1
            and findings[0].get("title") == "No issues found"
        )
        if not is_generic:
            break  # Claude wrote something specific — leave it alone

        crit, warn = osv_severity_counts(osv_vulns)
        noun = "dependency" if osv_checked == 1 else "dependencies"

        if not osv_vulns:
            summary = (
                f"Checked all {osv_checked} {noun} against the public OSV.dev "
                "vulnerability database — none have known vulnerabilities."
            )
            layer["expert"]["summary"] = summary
            layer["expert"]["findings"] = [{
                "severity": "passing",
                "title": f"All {osv_checked} {noun} checked, none vulnerable",
                "detail": summary, "file": "", "why_it_matters": "",
            }]
            layer["learner"]["findings_plain"] = [{
                "severity": "passing",
                "plain_title": f"All {osv_checked} {noun} checked — all clear",
                "plain_detail": (
                    f"Verilay checked every one of your app's {osv_checked} code libraries against a "
                    "public database of known security problems. None of them have a known issue."
                ),
                "real_world_impact": "", "action": "",
            }]
        else:
            sev = "critical" if crit > 0 else "warning"
            vuln_noun = "dependency has" if len(osv_vulns) == 1 else "dependencies have"
            summary = (
                f"Checked {osv_checked} {noun} against OSV.dev — found {len(osv_vulns)} with known "
                f"vulnerabilities ({crit} serious, {warn} less severe)."
            )
            layer["status"] = sev
            layer["expert"]["summary"] = summary
            layer["expert"]["findings"] = [{
                "severity": sev,
                "title": f"{len(osv_vulns)} {vuln_noun} known vulnerabilities",
                "detail": summary, "file": "",
                "why_it_matters": "Outdated libraries are one of the most common ways AI-built apps get compromised.",
            }]
            layer["learner"]["findings_plain"] = [{
                "severity": sev,
                "plain_title": f"{len(osv_vulns)} of your code libraries have known security problems",
                "plain_detail": (
                    f"Verilay checked all {osv_checked} of your app's code libraries against a public "
                    f"database of known security problems and found {len(osv_vulns)} with a documented "
                    "issue."
                ),
                "real_world_impact": "A known, published weakness in one of your libraries could be used against your app.",
                "action": "Ask your AI builder to check for outdated dependencies and update them to their patched versions.",
            }]
        break
    return s3


def analyse_step4(repo_name, built_with, findings_summary):
    is_lovable = "lovable" in built_with.lower()
    is_replit  = "replit" in built_with.lower()
    platform   = "Lovable" if is_lovable else ("Replit" if is_replit else "your AI builder")

    prompt = (
        "Based on this analysis of " + repo_name + ":\n"
        + findings_summary +
        "\n\nIMPORTANT PLATFORM AWARENESS:\n"
        "- Lovable Cloud: .env auto-managed, NEVER suggest .env.example or env validation as a fix\n"
        "- Supabase JS client: uses {data,error} pattern NOT exceptions — do NOT suggest wrapping in try/catch\n"
        "- TanStack Query: loading/error/retry are BUILT IN — do NOT suggest implementing these\n"
        "- supabase/types.ts is auto-generated: do NOT suggest adding Zod or runtime validation\n"
        "- import.meta.env usage: do NOT flag as hardcoded values\n" +
        "PLATFORM AWARENESS — NEVER FLAG these correct patterns:\n"
        "- Supabase anon key in frontend: by design, security from RLS not hiding key\n"
        "- verify_jwt=false in config.toml: fine BY ITSELF (Lovable Cloud default) for public endpoints or functions that verify auth in their own code. EXCEPTION — DO flag as CRITICAL when verify_jwt=false AND the function uses the service-role key AND has no in-code auth/secret check AND performs data-modifying or destructive operations (e.g. a cron-triggered delete/cleanup). That specific combination is a real unauthenticated-access vulnerability, not a platform default\n"
        "- try/catch on Supabase: wrong pattern, use {data,error}\n"
        "- TanStack Query loading states: built in\n"
        "- Replit Auth isAuthenticated/isAdmin/requireAuth: valid OIDC\n"
        "- Firebase Auth onAuthStateChanged/getAuth: valid auth\n"
        "- Passwordless/magic links: valid secure auth\n"
        "- Drizzle ORM TypeScript schemas: type validation handled\n"
        "- Flask @app.route/jsonify/os.getenv(): correct patterns\n"
        "- Gunicorn: production WSGI server, never flag as dev server\n"
        "- NextAuth useSession/getServerSession: valid auth\n"
        "- Clerk clerkMiddleware/useUser: valid auth\n"
        "- Prisma client: ORM handles injection prevention\n"
        "- asyncHandler wrapper: handles async errors correctly\n"
        "- Public tools @auth-required:false or @public:true: intentionally public\n"
        "- Local-only apps with no server: no auth/API/DB findings apply\n"
        "ADVICE: investigate and advise first, never suggest competing libraries.\n\n"
        "- EXTERNAL SCRIPTS: if app.js/main.js referenced via <script src=> tag — JS is present externally, NEVER flag as missing. Also if the HTML source shows /static/app.js or any external .js reference, the JavaScript IS fully present.\\n"
        "- URL SCAN TRUNCATION: URL scans only fetch partial HTML — truncated CSS like .ll{{display:gr is normal. NEVER flag truncated URL content as broken or incomplete code.\\n"
        "- AI-POWERED TOOLS: if Anthropic/OpenAI/Gemini API present — AI IS the analysis engine, NEVER flag missing Prism/CodeMirror/AST parsers.\\n"
        "- MINIFIED CODE: truncated or minified CSS/JS in HTML is normal — NEVER flag as incomplete or broken. Minification/bundling is the sign of a CORRECT production build, NOT a problem: NEVER flag it as a security finding, an auth-verification blocker, or a reason the app 'cannot be reviewed'. Do not say minified code 'prevents security review'. At most mention once as informational, and NEVER let minification lower the grade or appear as a warning/critical.\\n\\n"
        "IMPORTANT GUIDANCE PHILOSOPHY: Generate ADVICE prompts not FIX prompts. "
        "The goal is to help non-developers investigate and understand issues safely — not to make sweeping changes. "
        "Every prompt should ask the AI builder to REVIEW and ADVISE first, then suggest targeted changes only if genuinely needed. "
        "NEVER suggest installing new libraries if equivalent ones exist. Check what validation, auth, and DB libraries are already in use and work with those. "
        "NEVER suggest rewriting working code. Only suggest adding what is genuinely missing. "
        "Frame every prompt as: investigate this area, advise what you find, suggest the minimal safe change if any.\n"
        "If the score is A or B with no critical issues, say 'No critical fixes needed' for FIX titles. "
        "Do NOT invent generic fixes that are not supported by the findings above.\n\n"
        "WHOLE-REPO DIRECTION: Verilay analysed only a SAMPLE of the codebase, not every file. In each advice prompt, instruct the AI builder to check this class of issue across the ENTIRE repository — not only the flagged location — and to confirm WITH EVIDENCE per file (e.g. 'for EVERY edge function, confirm it verifies the caller and filters queries by the authenticated user, and LIST any that do not') rather than answering yes/no. This surfaces issues in files Verilay did not read. GROUNDING RULE: state specifics (file names, exact patterns) ONLY about files actually shown in the analysis above; for everything else, ask the builder to check the PATTERN across all files — never invent a specific file or finding you were not shown.\n\n"
        "Respond ONLY with key:value pairs, one per line, no other text.\n\n"
        "COVERAGE — read carefully: Generate ONE advice prompt per critical or warning finding. "
        "List ALL critical findings FIRST (each as its own prompt), then warnings. "
        "NEVER omit or merge a critical finding — every critical MUST get its own prompt, even if you keep others brief. "
        "Produce up to 8 prompts total, one per finding, ordered criticals first then warnings.\\n"
        "For each finding output six keys with the literal numbered names below. Leave a whole block blank only if there is no finding at that position.\\n"
        "FIX_1_TITLE: short title of the highest-severity finding\\n"
        "FIX_1_SEV: critical|warning\\n"
        "FIX_1_WHY: why this specific finding matters\\n"
        "FIX_1_HOW: 2-3 investigation steps for this finding only\\n"
        "FIX_1_EFFORT: 5 minutes|30 minutes|1 hour|1 day\\n"
        "FIX_1_PROMPT: advice prompt specific to this finding — paste into " + platform + ". Begin: I received a security review flagging [specific issue]. Please review and advise without making changes yet\\n"
        "FIX_2_TITLE: next finding, criticals before warnings (empty if none)\\n"
        "FIX_2_SEV: critical|warning\\n"
        "FIX_2_WHY: why\\n"
        "FIX_2_HOW: how\\n"
        "FIX_2_EFFORT: effort\\n"
        "FIX_2_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_3_TITLE: next finding (empty if none)\\n"
        "FIX_3_SEV: critical|warning\\n"
        "FIX_3_WHY: why\\n"
        "FIX_3_HOW: how\\n"
        "FIX_3_EFFORT: effort\\n"
        "FIX_3_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_4_TITLE: next finding (empty if none)\\n"
        "FIX_4_SEV: critical|warning\\n"
        "FIX_4_WHY: why\\n"
        "FIX_4_HOW: how\\n"
        "FIX_4_EFFORT: effort\\n"
        "FIX_4_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_5_TITLE: next finding (empty if none)\\n"
        "FIX_5_SEV: critical|warning\\n"
        "FIX_5_WHY: why\\n"
        "FIX_5_HOW: how\\n"
        "FIX_5_EFFORT: effort\\n"
        "FIX_5_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_6_TITLE: next finding (empty if none)\\n"
        "FIX_6_SEV: critical|warning\\n"
        "FIX_6_WHY: why\\n"
        "FIX_6_HOW: how\\n"
        "FIX_6_EFFORT: effort\\n"
        "FIX_6_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_7_TITLE: next finding (empty if none)\\n"
        "FIX_7_SEV: critical|warning\\n"
        "FIX_7_WHY: why\\n"
        "FIX_7_HOW: how\\n"
        "FIX_7_EFFORT: effort\\n"
        "FIX_7_PROMPT: advice prompt specific to this finding only\\n"
        "FIX_8_TITLE: next finding (empty if none)\\n"
        "FIX_8_SEV: critical|warning\\n"
        "FIX_8_WHY: why\\n"
        "FIX_8_HOW: how\\n"
        "FIX_8_EFFORT: effort\\n"
        "FIX_8_PROMPT: advice prompt specific to this finding only\\n"
        "SEC_SECRETS: true|false (are secrets exposed in repo)\n"
        "SEC_AUTH: true|false (is auth properly configured)\n"
        "SEC_RLS: true|false (is row level security configured)\n"
        "SEC_DEPS: true|false (are dependencies current)\n"
        "SEC_HARDCODED: true|false (no hardcoded secrets in code)\n"
        "OPINION_GENERAL: complete self-contained prompt to paste into Claude or ChatGPT to verify these findings about " + repo_name + "\n"
        "OPINION_SECURITY: complete prompt to verify the security findings specifically\n"
        "OPINION_PROD: complete prompt asking if " + repo_name + " is ready for production\n"
    )

    text = call_claude_text(prompt, max_tokens=2000)
    lines = {}
    for line in text.strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            lines[key.strip().upper()] = val.strip()

    def parse_bool(val, default=True):
        if not val: return default
        return val.lower() not in ("false", "no", "0")

    fixes = []
    for i in range(1, 9):
        title = lines.get(f"FIX_{i}_TITLE", "")
        if not title or title.lower() in ("next fix", "next finding", ""):
            continue
        sev = lines.get(f"FIX_{i}_SEV", "warning").strip().lower()
        if sev not in ("critical", "warning"):
            sev = "warning"
        fixes.append({
            "priority": i,
            "severity": sev,
            "title": title,
            "why_it_matters": lines.get(f"FIX_{i}_WHY", ""),
            "how_to_fix": lines.get(f"FIX_{i}_HOW", ""),
            "estimated_effort": lines.get(f"FIX_{i}_EFFORT", "30 minutes"),
            "lovable_prompt": lines.get(f"FIX_{i}_PROMPT", ""),
            "general_prompt": lines.get(f"FIX_{i}_PROMPT", "")
        })
    # Criticals must always appear first, regardless of the order the model returned them in.
    # Python's sort is stable, so within each severity the model's ordering is preserved.
    fixes.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)
    for idx, f in enumerate(fixes, 1):
        f["priority"] = idx

    return {
        "part2_loaded": True,
        "top_fixes": fixes,
        "security_score": {
            "env_secrets_exposed":      not parse_bool(lines.get("SEC_SECRETS","false"), False),
            "auth_properly_configured": parse_bool(lines.get("SEC_AUTH","true")),
            "rls_likely_configured":    parse_bool(lines.get("SEC_RLS","true")),
            "dependencies_current":     parse_bool(lines.get("SEC_DEPS","true")),
            "no_hardcoded_secrets":     parse_bool(lines.get("SEC_HARDCODED","true"))
        },
        "second_opinion": {
            "summary_prompt":       lines.get("OPINION_GENERAL", ""),
            "security_prompt":      lines.get("OPINION_SECURITY", ""),
            "prod_checklist_prompt":lines.get("OPINION_PROD", "")
        }
    }



# ── Main analysis route — streams results as JSON events ───────────────────────
@app.route("/analyse-stream", methods=["POST"])
def analyse_stream():
    """Stream analysis results as newline-delimited JSON events."""
    ip = get_ip()
    allowed, reset_in = check_rate_limit(ip)
    if not allowed:
        def blocked():
            yield json.dumps({"event":"error","data":f"Rate limit reached. Try again in {reset_in//60} minutes."}) + "\n"
        return Response(stream_with_context(blocked()), mimetype="application/x-ndjson")

    method = request.form.get("method","github")

    def generate():
        try:
            # ── Fetch files ────────────────────────────────────────────
            yield json.dumps({"event":"status","data":"Reading your project files..."}) + "\n"

            if method == "github":
                url = request.form.get("github_url","").strip()
                if not url:
                    yield json.dumps({"event":"error","data":"Please enter a GitHub URL"}) + "\n"; return
                # Validate URL format
                if not any(host in url.lower() for host in ['github.com','gitlab.com','bitbucket.org','dev.azure.com']):
                    yield json.dumps({"event":"error","data":"Please enter a valid GitHub, GitLab, or Bitbucket URL"}) + "\n"; return
                if len(url) > 500:
                    yield json.dumps({"event":"error","data":"URL is too long"}) + "\n"; return
                files, tree, repo_name = fetch_github(url)
            elif method == "zip":
                f = request.files.get("zip_file")
                if not f:
                    yield json.dumps({"event":"error","data":"Please select a ZIP file"}) + "\n"; return
                zip_data = f.read()
                zip_size_mb = len(zip_data) / (1024 * 1024)
                if zip_size_mb > 100:
                    yield json.dumps({"event":"error","data":f"ZIP file is {zip_size_mb:.0f}MB — too large. Please exclude the node_modules folder from your ZIP and try again. Alternatively use the GitHub URL method which has no size limit."}) + "\n"; return
                files, tree, repo_name = fetch_zip(io.BytesIO(zip_data), f.filename)
            elif method == "url":
                url = request.form.get("live_url","").strip()
                if not url:
                    yield json.dumps({"event":"error","data":"Please enter a URL"}) + "\n"; return
                # Validate URL format
                if not url.startswith(('http://','https://')):
                    yield json.dumps({"event":"error","data":"Please enter a valid URL starting with http:// or https://"}) + "\n"; return
                if len(url) > 500:
                    yield json.dumps({"event":"error","data":"URL is too long"}) + "\n"; return
                files, tree, repo_name = fetch_url(url)
            else:
                yield json.dumps({"event":"error","data":"Unknown method"}) + "\n"; return

            if not files:
                yield json.dumps({"event":"error","data":"No readable files found. Try ZIP upload."}) + "\n"; return

            # ── Deterministic secret scan ───────────────────────────────
            # Runs before Claude, over every file we can reach — not the 25-file
            # sample. Costs nothing and returns the same answer every run. For
            # GitHub we pull the whole repo as one tarball; ZIP and URL scans
            # cover the files already fetched.
            yield json.dumps({"event":"status","data":"Checking every file for exposed keys..."}) + "\n"
            scan_findings, scan_files_count = [], 0
            _all_text = None
            try:
                if method == "github":
                    _owner, _, _repo = repo_name.partition("/")
                    _all_text = fetch_all_files_tarball(_owner, _repo, GITHUB_TOKEN)
                    scan_findings = scan_repo(_all_text)
                    scan_files_count = len(_all_text)
                else:
                    scan_findings = scan_repo(files)
                    scan_files_count = len(files)
            except Exception as _scan_err:
                # Never let the scan take down an analysis. Fall back to the
                # sampled files so we still catch something.
                print(f"Full scan failed, falling back to sample: {_scan_err}", flush=True)
                try:
                    scan_findings = scan_repo(files)
                    scan_files_count = len(files)
                except Exception as _scan_err2:
                    print(f"Secret scan skipped entirely: {_scan_err2}", flush=True)
            scan_block = to_prompt_block(scan_findings, scan_files_count)
            scan_critical = sum(1 for _f in scan_findings if _f.severity == "critical")
            scan_warning  = sum(1 for _f in scan_findings if _f.severity == "warning")

            # ── OSV.dev dependency check ─────────────────────────────────
            # Runs in the FREE scan too (Decision 6) — cheap, sub-second, and
            # personalised to whatever the visitor pasted in. Reuses the same
            # full-repo text the secret scan already fetched, so no extra
            # GitHub call. Free tier gets a count only, never package names or
            # CVE ids — that detail is what the deep scan sells.
            yield json.dumps({"event":"status","data":"Checking dependencies for known vulnerabilities..."}) + "\n"
            osv_vulns, osv_checked = [], 0
            try:
                osv_source = _all_text if _all_text is not None else files
                osv_vulns, osv_checked = check_dependencies(osv_source)
            except Exception as _osv_err:
                print(f"OSV dependency check skipped: {_osv_err}", flush=True)
            osv_teaser_block = osv_to_teaser_block(osv_vulns, osv_checked)
            osv_critical, osv_warning = osv_severity_counts(osv_vulns)

            yield json.dumps({"event":"status","data":f"Found {len(files)} files — detecting stack..."}) + "\n"

            # ── Step 1: Stack + overview ────────────────────────────────
            s1 = analyse_step1(files, tree, repo_name, method)
            s1["files_read"] = len(files)
            s1["files_total"] = len(tree) if tree else len(files)
            s1["file_breakdown"] = categorise_files(tree if tree else list(files.keys()))
            s1["files_analysed"] = sorted(files.keys())
            # Attach the scan here, not just to the saved report — otherwise the
            # verified-findings block only appears when someone reopens a saved
            # report, and is invisible during the live analysis.
            s1["secret_scan"] = to_report_dict(scan_findings, scan_files_count)
            s1["osv_scan"] = osv_to_teaser_dict(osv_vulns, osv_checked)
            s1["generated_at"] = datetime.now().strftime("%d %b %Y %H:%M")
            count = get_analysis_count()
            s1["analysis_count"] = count

            # Thin URL scan → ungraded preview. A URL exposes almost no real code,
            # so running the full layer analysis is wasted time and money, and grading
            # from near-zero findings would produce a misleading "A". Stop here with an
            # honest, explicitly ungraded preview that points the user to GitHub/ZIP.
            is_thin_url = (method == "url" and len(files) <= THIN_URL_FILES)
            if is_thin_url:
                s1["preview_only"] = True
                s1.setdefault("health", {})
                s1["health"]["score"] = None
                s1["health"]["critical"] = None
                s1["health"]["warnings"] = None
                s1["health"]["passing"] = None

            yield json.dumps({"event":"step1","data":s1}) + "\n"

            if is_thin_url:
                preview = dict(s1)
                preview["layers"] = []
                # A key hardcoded into index.html is exactly what a URL scan can prove.
                # Carry it into the preview — the grade is withheld, the fact is not.
                preview["secret_scan"] = to_report_dict(scan_findings, scan_files_count)
                report_id = save_report_data(preview)
                try:
                    increment_analysis_count(score=None, method=method)
                except Exception as _inc_err:
                    print(f"Stats increment failed (non-critical): {_inc_err}", flush=True)
                yield json.dumps({"event":"saved","data":{"report_id":report_id}}) + "\n"
                yield json.dumps({"event":"layers_complete","data":{}}) + "\n"
                return

            # ── Steps 2 + 3 in parallel ────────────────────────────────
            yield json.dumps({"event":"status","data":"Analysing layers in parallel..."}) + "\n"
            import concurrent.futures
            s2 = {"layers":[]}
            s3 = {"layers":[]}
            s2_err = None
            s3_err = None
            # Run in parallel with keepalive pings to prevent Railway timeout
            import time as _time
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f2 = executor.submit(analyse_step2, files, repo_name, scan_block)
                f3 = executor.submit(analyse_step3, files, repo_name, osv_teaser_block)
                # Send keepalive every 20s while waiting — prevents Railway 30s timeout
                deadline = _time.time() + 90
                while _time.time() < deadline:
                    done2 = f2.done()
                    done3 = f3.done()
                    if done2 and done3:
                        break
                    yield json.dumps({"event":"status","data":"Analysing your codebase — layers will appear shortly..."}) + "\n"
                    _time.sleep(20)
                try:
                    s2 = f2.result(timeout=30)
                except Exception as e:
                    s2_err = str(e)
                try:
                    s3 = f3.result(timeout=30)
                except Exception as e:
                    s3_err = str(e)
            # Now yield results from main thread
            if s2_err:
                yield json.dumps({"event":"step2_error","data":s2_err}) + "\n"
            else:
                yield json.dumps({"event":"step2","data":s2}) + "\n"
            if s3_err:
                yield json.dumps({"event":"step3_error","data":s3_err}) + "\n"
            else:
                s3 = apply_osv_library_fallback(s3, osv_vulns, osv_checked)
                yield json.dumps({"event":"step3","data":s3}) + "\n"

            # ── Auto-save partial report ────────────────────────────────
            partial = dict(s1)
            partial["layers"] = s2.get("layers",[]) + s3.get("layers",[])
            # Derive the score and counts FROM the actual layer findings rather than
            # step 1's separate guess, so the header can never contradict the layers
            # and the grade is a deterministic result of counting, not a re-rolled judgment.
            _crit = _warn = _pass = 0
            for _layer in partial["layers"]:
                for _f in _layer.get("expert", {}).get("findings", []):
                    _sev = (_f.get("severity") or "").lower()
                    if _sev == "critical":
                        _crit += 1
                    elif _sev == "warning":
                        _warn += 1
                    elif _sev == "passing":
                        _pass += 1
            # The scanner sets a FLOOR the model cannot talk its way under. A key we
            # verified by reading the file is a fact, so if Claude reported fewer
            # criticals than the scanner confirmed, the scanner wins. max() rather
            # than addition, because step 2 was told to include the scanned findings
            # in its layers — adding would count the same key twice. Same reasoning
            # for OSV: a named CVE against a version we can read in the manifest is
            # a fact, not a judgement call.
            _crit = max(_crit, scan_critical, osv_critical)
            _warn = max(_warn, scan_warning, osv_warning)
            partial.setdefault("health", {})
            partial["health"]["critical"] = _crit
            partial["health"]["warnings"] = _warn
            partial["health"]["passing"] = _pass
            partial["health"]["score"] = grade_from_counts(_crit, _warn)
            partial["secret_scan"] = to_report_dict(scan_findings, scan_files_count)
            report_id = save_report_data(partial)
            try:
                increment_analysis_count(score=partial.get("health", {}).get("score"), method=method)
            except Exception as _inc_err:
                print(f"Stats increment failed (non-critical): {_inc_err}", flush=True)
            yield json.dumps({"event":"saved","data":{"report_id":report_id}}) + "\n"

            # ── Done with layers ────────────────────────────────────────
            yield json.dumps({"event":"layers_complete","data":{}}) + "\n"

        except Exception as e:
            yield json.dumps({"event":"error","data":str(e)}) + "\n"

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson")


@app.route("/analyse-step4", methods=["POST"])
def run_step4():
    """Step 4 — triggered by user clicking Part 2."""
    try:
        data = request.get_json()
        repo_name      = data.get("repo_name","")
        built_with     = data.get("built_with","")
        findings       = data.get("findings_summary","")
        report_id      = data.get("report_id","")

        # Truncate findings if too long to prevent timeout. Raised from 800 —
        # that cap predates per-finding detail being included here at all, and
        # was already almost the whole budget for just the header line plus
        # bare layer statuses. A real multi-finding report needs more room.
        if len(findings) > 3000:
            findings = findings[:3000] + '...'
        result = analyse_step4(repo_name, built_with, findings)

        # Update saved report with Part 2 data
        print(f"Part 2 update: report_id={report_id}, has_supabase={_HAS_SUPABASE}", flush=True)
        print(f"Part 2 result keys: {list(result.keys())}")
        print(f"top_fixes count: {len(result.get('top_fixes',[]))}")
        if report_id:
            p2_data = {
                "top_fixes":     result.get("top_fixes",[]),
                "security_score":result.get("security_score",{}),
                "second_opinion":result.get("second_opinion",{}),
            }
            if _HAS_SUPABASE:
                try:
                    res = _sb.table("reports").select("data").eq("id", report_id).execute()
                    if res.data:
                        merged = dict(res.data[0]["data"])
                        print(f"Existing keys before merge: {list(merged.keys())[:5]}", flush=True)
                        merged.update(p2_data)
                        print(f"Merged keys after update: {[k for k in merged.keys() if k in ['top_fixes','security_score','second_opinion']]}", flush=True)
                        upd = _sb.table("reports").update({"data": merged}).eq("id", report_id).execute()
                        print(f"✓ Part 2 saved to Supabase for {report_id}, updated rows: {len(upd.data)}", flush=True)
                    else:
                        print(f"✗ Report {report_id} not found in Supabase", flush=True)
                except Exception as e:
                    print(f"✗ Part 2 Supabase error: {e}", flush=True)
            if report_id in _reports:
                _reports[report_id]["data"].update(p2_data)

        result["part2_loaded"] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/report-data/<report_id>")
def report_data(report_id):
    """Return report JSON for loading in history view."""
    data = get_report_data(report_id)
    if not data:
        return jsonify({"error": "Report not found or expired"}), 404
    return jsonify(data)


@app.route("/verify-finding", methods=["POST"])
def verify_finding():
    """Mark a finding as verified by the user's AI builder."""
    try:
        data = request.get_json()
        report_id = data.get("report_id", "")
        finding_key = data.get("finding_key", "")
        builder_response = data.get("builder_response", "")
        verdict = data.get("verdict", "verified")  # verified | fixed | false_positive

        if not report_id or not finding_key:
            return jsonify({"ok": False, "error": "Missing report_id or finding_key"})

        if _HAS_SUPABASE:
            try:
                res = _sb.table("reports").select("data").eq("id", report_id).execute()
                if res.data:
                    report_data = dict(res.data[0]["data"])
                    # Store verifications
                    verifications = report_data.get("verifications", {})
                    verifications[finding_key] = {
                        "verdict": verdict,
                        "builder_response": builder_response[:500],
                        "verified_at": _dt.datetime.utcnow().isoformat()
                    }
                    report_data["verifications"] = verifications
                    _sb.table("reports").update({"data": report_data}).eq("id", report_id).execute()
                    return jsonify({"ok": True, "verifications": verifications})
            except Exception as e:
                print(f"Verify finding error: {e}", flush=True)

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/delete-report/<report_id>", methods=["POST"])
def delete_report(report_id):
    """Delete a report — strips sensitive data but keeps stats."""
    try:
        if not report_id or len(report_id) < 8:
            return jsonify({"ok": False, "error": "Invalid report ID"})
        if _HAS_SUPABASE:
            try:
                # Anonymise rather than delete — keeps stats accurate
                _sb.table("reports").update({
                    "data": {"deleted": True, "deleted_at": _dt.datetime.utcnow().isoformat()}
                }).eq("id", report_id).execute()
                print(f"✓ Report anonymised: {report_id}", flush=True)
                return jsonify({"ok": True})
            except Exception as e:
                print(f"Delete error: {e}", flush=True)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/waitlist", methods=["POST"])
def waitlist():
    """Save email to waitlist table."""
    try:
        data = request.get_json()
        email = data.get("email", "").strip().lower()
        analyses_count = data.get("analyses_count", 0)
        source = data.get("source", "nudge")

        if not email or "@" not in email:
            return jsonify({"ok": False, "error": "Invalid email"})

        if _HAS_SUPABASE:
            try:
                _sb.table("waitlist").insert({
                    "email": email,
                    "analyses_count": analyses_count,
                    "source": source
                }).execute()
                print(f"✓ Waitlist signup: {email}", flush=True)
                return jsonify({"ok": True})
            except Exception as e:
                # Duplicate email — already signed up
                if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                    return jsonify({"ok": True, "already": True})
                print(f"Waitlist error: {e}", flush=True)

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/feedback", methods=["POST"])
def feedback():
    try:
        data = request.get_json()
        helpful = data.get("helpful")
        comment = data.get("comment", "")
        email = (data.get("email") or "").strip()
        report_id = data.get("report_id", "")
        print(f"Feedback: helpful={helpful} report={report_id} email={email} comment={comment[:100]}", flush=True)
        if _HAS_SUPABASE and report_id:
            try:
                merged = dict(get_report_data(report_id) or {})
                merged["feedback_helpful"] = helpful
                if comment:
                    merged["feedback_comment"] = comment
                if email:
                    merged["feedback_email"] = email
                _sb.table("reports").update({"data": merged}).eq("id", report_id).execute()
            except:
                pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stats")
def stats():
    count = get_analysis_count()
    return jsonify({"analyses": count, "formatted": f"{count:,}"})


@app.route("/self-monitor-health")
def self_monitor_health():
    """Diagnostic view into the self-monitoring teaser — added because
    Railway's log viewer isn't always easy to search, and this table never
    holds anything more sensitive than an access/infra error string (see
    verilay_self_monitor.health_data's docstring)."""
    return jsonify(self_monitor.health_data())


# Blog routes — paste this into app.py before the sitemap route

BLOG_POSTS = [
    {
        "slug": "free-tool-limit-wasnt-real",
        "title": "My Free Tool Had a Limit. It Turned Out the Limit Wasn&rsquo;t Real.",
        "date": "August 11, 2026",
        "category": "Build",
        "excerpt": "My AI bill went up, so I went looking. The rate limit had been counting a number visitors write themselves — so it had never limited anything.",
        "medium_url": None,
        "read_time": "5 min read",
        "featured": False,
        "body": """
<p>Verilay is free. No account, no card, paste in your app and get an answer.</p>
<p>What isn't free is running it. Every analysis makes several calls to Claude, and each one
costs me somewhere between two and three cents. That's fine when a handful of people use it.
It's a different conversation when a few hundred do.</p>
<p>Last week my bill went up enough that I went looking for why. What I found wasn't a surge
of users. It was a limit that had never worked.</p>

<h2>The thing I thought I had</h2>
<p>Verilay has always had a rate limit: <strong>ten analyses per hour, per person.</strong>
More than generous — most people run one, fix something, run it again. Ten is plenty, and it
means nobody can sit there in a loop spending my money.</p>
<p>The code was simple enough. For each visitor, keep a list of when they last ran something,
throw away anything older than an hour, and refuse the eleventh.</p>
<p>The bit I got wrong was the words <em>each visitor</em>.</p>

<h2>How a website knows who you are</h2>
<p>When your browser asks a website for a page, it sends along some extra information: what
browser you're using, what language you prefer, and — if the request passed through anything
in the middle — where it came from.</p>
<p>That last one lives in something called <code>X-Forwarded-For</code>. It's a list of
addresses, added to by each stop along the way, so the final website can work out who
originally asked.</p>
<p>Verilay was reading the first name on that list.</p>
<p>Here's the problem. <strong>The first name on that list is whatever your browser put
there.</strong> Not what the network worked out. What the visitor themselves supplied.</p>
<p>It's a clipboard at the door where people write their own name, and I was counting the
names on the clipboard.</p>
<p>Anyone who wanted unlimited free analyses only had to write a different name each time.
Not a clever exploit. Not a tool you'd have to download. Change one line in the request and
the limit disappears, because every request looks like a brand new person who has never
visited before.</p>
<p>The limit had been there since the beginning. It just wasn't limiting anything.</p>

<h2>And then it got slightly worse</h2>
<p>While I was in there I found a second, smaller version of the same problem.</p>
<p>To handle several people at once, Verilay doesn't run as one program. It runs as four
identical copies, and whichever one is free takes your request.</p>
<p>Each copy keeps its own list of who's been doing what. And they don't talk to each
other.</p>
<p>So even for an honest visitor who wasn't faking anything, "ten per hour" was really up to
forty — ten at each of four doors, none of the doormen aware the others exist.</p>

<h2>The fix</h2>
<p>For the first problem, the fix was small. Verilay sits behind Cloudflare, and Cloudflare
adds its own record of where a request genuinely came from — one the visitor can't write on,
because Cloudflare overwrites anything they put there. Read that instead of the clipboard and
the limit starts working.</p>
<p>There was a small indignity here. Verilay had <strong>two</strong> functions doing this
same job, in two different parts of the code. One of them already did it correctly. The two
had been written at different times and drifted apart, and I'd been looking at the wrong one
for months. There's now only one, and the other calls it.</p>
<p>The four-doors problem is a bigger fix — the copies need somewhere shared to keep the
count — and I haven't done it yet. It's on the list. But it's a four-times-too-loose problem,
not an infinitely-loose one, which is a much better place to be.</p>

<h2>What this actually costs</h2>
<p>Some real numbers, because I don't think people building free tools talk about this
enough.</p>
<table>
<tr><th>Scenario</th><th>Cost to me</th></tr>
<tr><td>One analysis</td><td>2–3 cents</td></tr>
<tr><td>A good day — 100 people</td><td>$2–3</td></tr>
<tr><td>A launch — 1,000 analyses</td><td>$20–30</td></tr>
<tr><td>One person in a loop, unlimited</td><td>However long they feel like</td></tr>
</table>
<p>The first three are fine. I'd happily pay $30 for a thousand people trying something I
built. The fourth is the one that keeps you up, and it's the one the broken limit had left
wide open.</p>
<p>Worth saying plainly: a free tool with an AI behind it is a different animal from a normal
free website. A normal website costs about the same whether ten people visit or ten thousand.
Mine costs money <em>per use</em>, forever. That changes what "free" can mean, and it's why
I'll eventually charge for something.</p>

<h2>If you're running something similar</h2>
<p>Three things worth checking today, none of which take long.</p>
<p><strong>Do you actually have a limit?</strong> Not "did you mean to add one" — go and try
to break it. Run your thing eleven times in a row. If the eleventh works, you don't have a
limit, whatever the code says. I'd never done this, which is exactly why I didn't know.</p>
<p><strong>Are you trusting something the visitor sent you?</strong> Anything arriving from
someone's browser is a suggestion, not a fact. Names, addresses, counts, prices, who they
claim to be. If a decision that costs you money depends on it, that decision can be bought
for nothing.</p>
<p><strong>Do you have a ceiling?</strong> I've since turned on automatic top-ups for my AI
credits so the tool doesn't stop mid-sentence when they run out. That solved one problem and
created another: "stops working" became "bills my card." So there's now a monthly cap
alongside it. Automatic top-ups without a cap is a trapdoor, and I nearly left it open.</p>

<h2>The uncomfortable part</h2>
<p>I build a tool that checks other people's apps for exactly this class of mistake.</p>
<p>I'd like to say I found this because I'm thorough. I found it because I looked at a bill,
got a small fright, and went digging. The check I'd have needed didn't exist — not in
Verilay, not anywhere I'd thought to look.</p>
<p>That's most of what I've learned building this thing. The problems aren't usually hiding in
the clever parts. They're in the parts you wrote early, believed you'd finished, and never
went back to.</p>
""",
    },
    {
        "slug": "part-of-my-ai-tool-that-shouldnt-be-ai",
        "title": "The Part of My AI Tool That Shouldn&rsquo;t Have Been AI",
        "date": "July 24, 2026",
        "category": "Build",
        "excerpt": "My security tool asked an AI to look for passwords in 25 of your files. Finding a password isn't a judgement call — it's a lookup. What changed when I stopped asking.",
        "medium_url": None,
        "read_time": "7 min read",
        "featured": True,
        "body": """
<p>Back in June I wrote about
<a href="/blog/ran-own-security-tool-different-grade">running Verilay on Verilay and getting a
different grade almost every time</a>. Same app, same code, different answer. For a tool whose
entire job is telling you whether something is safe, that's not a great look, and I said
so.</p>
<p>I've now fixed a big part of that. The fix was to take the AI out.</p>
<p>Not all of it. Verilay is still built on Claude and always will be. But there was one job I
had given the AI that it was never the right tool for, and once I saw it I couldn't unsee
it.</p>

<h2>What it was doing</h2>
<p>Verilay reads your code and tells you what's in it. One of the things it checks is whether
you've left a password or an API key sitting in a file — a real and very common problem in
apps built with Lovable or Replit, because the AI that built your app will cheerfully paste a
key straight into the code if you're not watching.</p>
<p>The way I had built that check was, roughly:</p>
<blockquote><p>Here are 25 of your files. Have a look through them for anything that looks
like an API key.</p></blockquote>
<p>And Claude would look, and usually find them, and explain them beautifully.</p>
<p>It took me an embarrassingly long time to notice the three things wrong with that.</p>
<p><strong>It was only looking at 25 files.</strong> Verilay picks the 25 files most likely to
matter and sends those. If your app has 300 files — which is normal — then the other 275 were
never looked at. A key sitting in file number 26 was invisible. Not "probably found", not
"less likely to be found". Invisible.</p>
<p><strong>It gave a different answer each time.</strong> Not wildly different, but enough.
Ask an AI to skim for something and you're asking for a judgement, and judgements vary. That
was the wobbling grade from my June post, showing up in the one place where wobble is least
acceptable.</p>
<p><strong>It cost money every single time.</strong> Every analysis Verilay runs costs me a
few cents in AI credits. Some of those cents were being spent asking a very sophisticated
reasoning model to do something a wristwatch could do.</p>

<h2>The thing I finally noticed</h2>
<p>Finding an API key is not a judgement call.</p>
<p>An Amazon Web Services key always starts with the letters <code>AKIA</code> followed by
exactly sixteen more characters. Not usually. Always. A Stripe live key always starts
<code>sk_live_</code>. A private key file always begins with a line saying
<code>-----BEGIN PRIVATE KEY-----</code>.</p>
<p>These aren't things you weigh up. They're things you look up. It's the difference between
"is this a good password?" — a judgement — and "does this postcode exist?" — a lookup.</p>
<p>I was paying for judgement on a lookup.</p>
<p>So I wrote plain code to do it instead. A few hundred lines, no AI involved. It knows the
shapes of around twenty different kinds of key, it reads <strong>every file in your
project</strong>, it costs nothing, and it gives the same answer every single time because it
isn't deciding anything. It's matching.</p>

<h2>What changed</h2>
<table>
<tr><th></th><th>Before</th><th>After</th></tr>
<tr><td>Files checked for keys</td><td>25</td><td>All of them</td></tr>
<tr><td>Cost</td><td>Part of the AI bill</td><td>Nothing</td></tr>
<tr><td>Same answer twice?</td><td>Not reliably</td><td>Always</td></tr>
<tr><td>Evidence</td><td>"Claude thinks…"</td><td><code>config.ts</code>, line 42</td></tr>
</table>
<p>That last row is the one I care about most. Before, the tool said something looked risky.
Now it says exactly which file, exactly which line, and the first few characters of what it
found. You can go and look. You don't have to take anyone's word for it, mine or the AI's.</p>

<h2>The example that made it worth doing</h2>
<p>Here's the one that convinced me.</p>
<p>If your app uses Supabase — and if you built with Lovable, it almost certainly does — you
have two keys. They look nearly identical. Both are long strings of gibberish starting
<code>eyJ</code>.</p>
<p>One of them is the <strong>anon key</strong>. It's meant to be in your app, visible to
everyone. That's by design and it's fine.</p>
<p>The other is the <strong>service role key</strong>. It ignores every privacy rule you have
set up. Anyone holding it can read, change or delete every row in your database — every
customer, every address, every phone number — regardless of what permissions you
configured.</p>
<p>Putting the second one where the first one belongs is, I think, the single most damaging
mistake a non-developer can make with an AI-built app. And you would never spot it by eye,
because the two look the same.</p>
<p>The plain code can tell them apart. It unpacks the key and reads what's inside, which takes
about a thousandth of a second. It checks every file, so it doesn't matter where the key is
hiding.</p>
<p>The old way — asking an AI to skim 25 files — might have caught it. Might not have. Might
have caught it on Tuesday and missed it on Wednesday.</p>
<p>That's not good enough for something that serious.</p>

<h2>So what is the AI still doing?</h2>
<p>Everything that actually needs thinking about.</p>
<p>Because here's what the plain code produces:</p>
<pre><code>SUPA001  critical  src/config.ts:2  eyJhbG...</code></pre>
<p>Which is useless to you. It's useless to almost everyone, honestly. It's a fact with no
meaning attached.</p>
<p>The AI turns it into this:</p>
<blockquote><p>Your Supabase master key is in this file. It looks almost identical to the safe
public key, but it ignores every privacy rule you've set up — anyone who finds it can read,
change or delete every row in your database, including other people's personal details.</p>
<p>Remove it from this file, then go to Supabase → Project Settings → API and roll the
service_role key.</p></blockquote>
<p>That's the part I can't write rules for. Understanding what your app does, working out
which of your problems matters most, and explaining it to someone who has never written a line
of code — that's judgement, and it's exactly what the AI is extraordinary at.</p>
<p>The mistake wasn't using AI. The mistake was using it for the wrong half.</p>

<h2>The bit you can actually use</h2>
<p>If you're building anything with AI — an app, a tool, an automation — it's worth going
through it and asking one question of each part:</p>
<p><strong>Is this a judgement, or a lookup?</strong></p>
<p>Judgement is anything where a thoughtful person could reasonably disagree. What does this
app do? Which of these problems is most urgent? How do I explain this to someone who's
frightened? Give those to the AI. It's better at them than most people.</p>
<p>Lookups are anything with a right answer that doesn't change. Does this string match a
known pattern? Is this version number higher than that one? Is this date in the past? Write
those as ordinary rules — or ask the AI to write the rules for you once, and then run the
rules forever.</p>
<p>You'll spend less, wait less, and get the same answer twice in a row.</p>
<p>There's a version of this you may already be doing without noticing. If you've ever asked
ChatGPT to add up a column of numbers and got a slightly wrong total, that's the same mistake
in miniature. Arithmetic is a lookup. Don't ask for judgement on it.</p>

<h2>One more thing, since I'm being honest</h2>
<p>While I was in there, I found three real security holes in Verilay itself. In the security
tool. Not theoretical ones — the sort that would have been worth writing up if I'd found them
in someone else's app.</p>
<p>They're fixed now, and I'll write about them separately, because they deserve more room
than a footnote and because one of them is genuinely interesting: the dangerous part never
went anywhere near the box where users type things, which is exactly why I hadn't spotted
it.</p>
<p>Verilay's code has always been public, at
<a href="https://github.com/ekbm/verilay" target="_blank" rel="noopener">github.com/ekbm/verilay</a>.
I've said before that a tool asking you to trust it should let you check. That cuts both ways.
It means anyone can find what I missed — and someone finding it is a much better outcome than
nobody looking.</p>
""",
    },
    {
        "slug": "background-job-delete-user-data",
        "title": "The Background Job in Your AI-Built App That Could Delete Every User's Data",
        "date": "June 26, 2026",
        "category": "Guide",
        "excerpt": "The riskiest parts of an AI-built app are often the ones with no screen — background jobs and scheduled tasks. Here's a real one, and how to check yours.",
        "medium_url": "https://medium.com/@mosesekbote/the-background-job-in-your-ai-built-app-that-could-delete-every-users-data-37249e40a342",
        "read_time": "5 min read",
        "featured": False,
    },
    {
        "slug": "trust-ai-app-real-user-data",
        "title": "Can You Trust an AI-Built App with Real User Data?",
        "date": "June 19, 2026",
        "category": "Guide",
        "excerpt": "When can you safely go solo with a Lovable or Replit app, and when should you get a second opinion before trusting it with real user data?",
        "medium_url": "https://medium.com/@mosesekbote/can-you-trust-an-ai-built-app-with-real-user-data-dcdca90ae5a6",
        "read_time": "4 min read",
        "featured": False,
    },
    {
        "slug": "3-ways-test-ai-generated-software",
        "title": "3 Ways Non-Developers Can Test AI-Generated Software",
        "date": "June 18, 2026",
        "category": "Guide",
        "excerpt": "Three no-code testing tricks to stress-test your AI-built app before launch: the double-submit test, the malicious-input test, and the mobile audit.",
        "medium_url": "https://medium.com/@mosesekbote/3-ways-non-developers-can-test-ai-generated-software-3d898f5a578a",
        "read_time": "5 min read",
        "featured": False,
    },
    {
        "slug": "beyond-the-prompt-ai-app-works",
        "title": "Beyond the Prompt: How to Make Sure Your AI-Built App Actually Works",
        "date": "June 18, 2026",
        "category": "Guide",
        "excerpt": "A jargon-free guide to testing your AI-built app: the 'try to break it' method, what production-ready really means, and when a human second opinion is worth it.",
        "medium_url": "https://medium.com/@mosesekbote/beyond-the-prompt-how-to-make-sure-your-ai-built-app-actually-works-472968116646",
        "read_time": "4 min read",
        "featured": False,
    },
    {
        "slug": "ai-app-now-what-4-step-checklist",
        "title": "I Built an App with AI&hellip; Now What? The 4-Step Checklist Before You Launch",
        "date": "June 17, 2026",
        "category": "Guide",
        "excerpt": "The non-developer checklist before you launch: the fake-identity test, the chaos test, the device reality check, and a launch safety net.",
        "medium_url": "https://medium.com/@mosesekbote/i-built-an-app-with-ai-now-what-the-4-step-checklist-before-you-launch-7ebe5879c095",
        "read_time": "5 min read",
        "featured": False,
    },
    {
        "slug": "ran-own-security-tool-different-grade",
        "title": "I Ran My Own Security Tool on My Own App &mdash; and Got a Different Grade Every Time",
        "date": "June 17, 2026",
        "category": "Story",
        "excerpt": "My own tool gave my own app a different grade every time. What inconsistent AI scoring taught me &mdash; and how I fixed it.",
        "medium_url": "https://medium.com/@mosesekbote/i-ran-my-own-security-tool-on-my-own-app-and-got-a-different-grade-every-time-5b153447f49c",
        "read_time": "6 min read",
        "featured": False,
    },
    {
        "slug": "built-ai-apps-no-idea-secure",
        "title": "I Built Several AI Apps and Had No Idea If Any of Them Were Secure",
        "date": "June 10, 2026",
        "category": "Story",
        "excerpt": "The moment I realised my AI-built apps might be vulnerable and what I did about it.",
        "medium_url": "https://medium.com/@mosesekbote/i-built-an-ai-app-and-had-no-idea-if-it-was-secure-cb6f54be8e27",
        "read_time": "6 min read",
        "featured": False,
    },
    {
        "slug": "how-built-security-tool-without-developer",
        "title": "How I Built a Security Tool Without Being a Developer",
        "date": "June 13, 2026",
        "category": "Build",
        "excerpt": "The technical journey — Flask, Claude API, smart file selection, and the false positive problem.",
        "medium_url": "https://medium.com/@mosesekbote/how-i-built-a-security-tool-without-being-a-developer-5f1ed4da32ec",
        "read_time": "7 min read",
        "featured": False,
    },
    {
        "slug": "advise-not-fix-non-developer-security",
        "title": "Why Advise Not Fix Is the Only Safe Approach for Non-Developer Security",
        "date": "June 14, 2026",
        "category": "Philosophy",
        "excerpt": "Three real conversations that proved the model and what the B grade actually means.",
        "medium_url": "https://medium.com/@mosesekbote/why-advise-not-fix-is-the-only-safe-approach-for-non-developer-security-a7abf901d2ff",
        "read_time": "7 min read",
        "featured": False,
    },
    {
        "slug": "evident-ai-c-to-b",
        "title": "How Evident-AI Went From C to B",
        "date": "June 12, 2026",
        "category": "Case Study",
        "excerpt": "Two real vulnerabilities, one false positive, three advice conversations with Replit. Zero broken features.",
        "medium_url": None,
        "read_time": "6 min read",
        "featured": False,
    },
]

CAT_COLORS = {
    "Story": ("#EEEDFE", "#3C3489"),
    "Build": ("#E1F5EE", "#085041"),
    "Philosophy": ("#FAEEDA", "#633806"),
    "Case Study": ("#E6F1FB", "#0C447C"),
    "Feature": ("#FCEBEB", "#A32D2D"),
    "Guide": ("#DEF1F0", "#0B5E57"),
}

BLOG_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:800px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1rem}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
a.card{display:block;text-decoration:none;background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;transition:box-shadow .15s}
a.card:hover{box-shadow:0 4px 20px rgba(0,0,0,.08)}
"""

def _render_card(p, big=False):
    bg, fg = CAT_COLORS.get(p["category"], ("#fff", "#666"))
    is_soon = p.get("coming_soon", False)
    link = p["medium_url"] if p["medium_url"] else "/blog/" + p["slug"]
    target = 'target="_blank" rel="noopener"' if p["medium_url"] else ""
    ext = " &nearr;" if p["medium_url"] else ""
    if is_soon:
        link = "#"
        target = ""
        ext = ""
    pad = "2rem" if big else "1.25rem"
    title_size = "21px" if big else "16px"
    return (
        '<a href="' + link + '" ' + target + ' class="card" style="padding:' + pad + '">'
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:.6rem">'
        '<span style="font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;background:' + bg + ';color:' + fg + '">' + p["category"] + '</span>'
        '<span style="font-size:11px;color:#6b6966">' + p["date"] + ' - ' + p["read_time"] + '</span>'
        '</div>'
        '<div style="font-size:' + title_size + ';font-weight:700;color:' + ('#9999aa' if is_soon else '#1a1917') + ';margin-bottom:.4rem;line-height:1.3">' + p["title"] + ext + ('&nbsp;<span style="font-size:10px;background:#f0f0f0;color:#999;padding:2px 7px;border-radius:10px;font-weight:500">Coming soon</span>' if is_soon else '') + '</div>'
        '<div style="font-size:13px;color:#6b6966;line-height:1.55">' + p["excerpt"] + '</div>'
        '</a>'
    )


@app.route("/blog")
def blog():
    featured = next((p for p in BLOG_POSTS if p.get("featured")), None)
    others = [p for p in BLOG_POSTS if not p.get("featured")]
    featured_html = _render_card(featured, big=True) if featured else ""
    grid_html = "".join("<div>" + _render_card(p) + "</div>" for p in others)

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blog - Verilay</title>
<meta name="description" content="Security insights, case studies and building lessons for non-developers.">
<style>""" + BLOG_CSS + """</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">From the team</div>
    <h1 style="font-size:28px;font-weight:700;margin-bottom:.5rem">Verilay Blog</h1>
    <p style="color:#6b6966;font-size:15px">Security insights, case studies and building lessons for non-developers who build real things.</p>
  </div>
  """ + featured_html + """
  <div style="font-size:12px;font-weight:600;color:#6b6966;letter-spacing:.06em;text-transform:uppercase;margin-bottom:.75rem;margin-top:1.5rem">More posts</div>
  <div class="grid">""" + grid_html + """</div>
  <div style="margin-top:3rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <p style="font-size:13px;color:#6b6966">Ready to check your own app?</p>
    <a href="/" style="display:inline-block;margin-top:.75rem;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
<script>
(function() {
  function initBurger() {
    var btn = document.getElementById("burger-btn");
    var menu = document.getElementById("burger-menu");
    if (!btn || !menu) return;

    function openMenu() {
      menu.style.display = "block";
      btn.innerHTML = '<i class="ti ti-x" style="font-size:18px"></i>';
    }
    function closeMenu() {
      menu.style.display = "none";
      btn.innerHTML = '<i class="ti ti-menu-2" style="font-size:18px"></i>';
    }
    function toggleMenu(e) {
      e.preventDefault();
      e.stopPropagation();
      menu.style.display === "block" ? closeMenu() : openMenu();
    }

    // Use both touch and click for reliability on mobile
    btn.addEventListener("touchend", toggleMenu, {passive: false});
    btn.addEventListener("click", function(e) {
      // Only fire click if not already handled by touch
      if (!e._handledByTouch) toggleMenu(e);
    });
    btn.addEventListener("touchstart", function(e) {
      e._handledByTouch = true;
    }, {passive: true});

    // Close on outside tap/click
    document.addEventListener("touchend", function(e) {
      if (menu.style.display === "block" && !menu.contains(e.target) && !btn.contains(e.target)) {
        closeMenu();
      }
    }, {passive: true});
    document.addEventListener("click", function(e) {
      if (menu.style.display === "block" && !menu.contains(e.target) && !btn.contains(e.target)) {
        closeMenu();
      }
    });

    // Close when a menu link is tapped
    menu.querySelectorAll("a").forEach(function(a) {
      a.addEventListener("touchend", function() { closeMenu(); }, {passive: true});
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initBurger);
  } else {
    initBurger();
  }
})();
</script>

</body>
</html>"""



def render_evident_case_study():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>How Evident-AI Went From C to B - Verilay Case Study</title>
<meta name="description" content="Two real vulnerabilities, one false positive, three advice conversations. Zero broken features.">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
.wrap{max-width:680px;margin:0 auto;padding:0 1.5rem 3rem}
h2{font-size:18px;font-weight:700;margin:2rem 0 .75rem}
p{color:#4a4846;line-height:1.75;margin-bottom:1rem;font-size:15px}
.finding{background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem;margin:.5rem 0}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;margin-right:6px}
.tag-critical{background:#FCEBEB;color:#A32D2D}
.tag-false{background:#E1F5EE;color:#085041}
blockquote{border-left:3px solid #534AB7;padding:.75rem 1rem;margin:1rem 0;background:#EEEDFE;border-radius:0 8px 8px 0;font-size:14px;color:#3C3489;line-height:1.65;font-style:italic}
.score{display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:10px;font-size:22px;font-weight:700}
</style>
</head>
<body>
<nav>
  <a href="/" style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:17px;text-decoration:none;color:#1a1917">
    <svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg>
    Verilay
  </a>
  <a href="/blog" style="font-size:13px;color:#6b6966;text-decoration:none">&#8592; Blog</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:.75rem">
      <span style="font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;background:#E6F1FB;color:#0C447C">Case Study</span>
      <span style="font-size:12px;color:#6b6966">June 12, 2026 &middot; 6 min read</span>
    </div>
    <h1 style="font-size:28px;font-weight:700;line-height:1.25;margin-bottom:1rem">How Evident-AI Went From C to B</h1>
    <p style="font-size:16px;color:#6b6966;line-height:1.6">Two real vulnerabilities. One false positive. Three advice conversations with Replit. Zero broken features.</p>
  </div>

  <div style="display:flex;align-items:center;gap:1.5rem;background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1.25rem;margin-bottom:2rem">
    <div style="text-align:center"><div class="score" style="background:#FEF9C3;color:#854D0E">C</div><div style="font-size:11px;color:#6b6966;margin-top:.35rem">Before</div></div>
    <div style="font-size:24px;color:#6b6966">&#8594;</div>
    <div style="text-align:center"><div class="score" style="background:#EFF6FF;color:#1D4ED8">B</div><div style="font-size:11px;color:#6b6966;margin-top:.35rem">After</div></div>
    <div style="margin-left:.5rem;font-size:13px;color:#4a4846;line-height:1.6"><strong>2 critical findings fixed</strong><br>1 false positive identified<br>No features broken</div>
  </div>

  <h2>The app</h2>
  <p>Evident-AI is a study and document management platform built on Replit using PostgreSQL and OpenAI. Real users, real data, real login system — built without a traditional development background using AI-assisted development.</p>
  <p>Like most apps built this way it worked perfectly. Users could sign up, upload documents, and use the AI features. But working and secure are two different things.</p>

  <h2>Running the scan</h2>
  <p>I submitted the Evident-AI GitHub repository to Verilay. The analysis read 18 files including package.json, auth middleware, API routes, database schema, and environment config. The result came back as a C grade with 2 critical findings and 3 warnings.</p>
  <div style="background:#FCEBEB;border:0.5px solid #E24B4A;border-radius:10px;padding:1rem;margin-bottom:1rem">
    <div style="font-weight:600;font-size:13px;color:#A32D2D;margin-bottom:.35rem">Score C &mdash; 2 critical findings</div>
    <div style="font-size:13px;color:#4a4846">Most AI-built apps score C on their first scan. It does not mean the app is broken &mdash; it means there are specific issues worth investigating.</div>
  </div>

  <h2>The findings</h2>
  <div class="finding">
    <div style="margin-bottom:.4rem"><span class="tag tag-critical">Critical</span><strong style="font-size:14px">Dependency vulnerabilities in package.json</strong></div>
    <p style="font-size:13px;margin-bottom:0">Two packages had known security vulnerabilities &mdash; protobufjs 7.5.4 and @google-cloud/storage 7.18. Both had patched versions available.</p>
  </div>
  <div class="finding">
    <div style="margin-bottom:.4rem"><span class="tag tag-critical">Critical</span><strong style="font-size:14px">API endpoints missing rate limiting</strong></div>
    <p style="font-size:13px;margin-bottom:0">The OpenAI-powered endpoints had no rate limiting. A malicious user could make hundreds of requests per minute &mdash; running up API costs with no ceiling.</p>
  </div>
  <div class="finding">
    <div style="margin-bottom:.4rem"><span class="tag" style="background:#E1F5EE;color:#085041">False positive</span><strong style="font-size:14px">Missing authentication on admin routes</strong></div>
    <p style="font-size:13px;margin-bottom:0">Verilay flagged admin routes as potentially unprotected. This was incorrect &mdash; Replit Auth was handling this correctly. The middleware was present but written in a pattern Verilay did not initially recognise.</p>
  </div>

  <h2>Three conversations with Replit</h2>
  <p>Instead of asking Replit to fix everything, each prompt asked it to investigate and explain first. This is the advise not fix approach.</p>

  <p><strong>Conversation 1 &mdash; Dependency vulnerabilities:</strong></p>
  <blockquote>I received a security review flagging protobufjs 7.5.4 and @google-cloud/storage 7.18 as having known vulnerabilities. Can you review these dependencies and advise what the actual risk is for this app, and whether updating them is safe?</blockquote>
  <p>Replit confirmed both were genuine. It updated protobufjs to 7.6.2 and @google-cloud/storage to 7.19. No features broke.</p>

  <p><strong>Conversation 2 &mdash; Rate limiting:</strong></p>
  <blockquote>I received a security review noting that the OpenAI API endpoints have no rate limiting. Can you review the current endpoint structure and advise what rate limiting approach would work here without breaking existing functionality?</blockquote>
  <p>Replit agreed this was a real risk. It added per-user rate limiting &mdash; 10 requests per minute per user with a clear error message when exceeded. Total time: 20 minutes.</p>

  <p><strong>Conversation 3 &mdash; Admin route authentication:</strong></p>
  <blockquote>I received a security review flagging admin routes as potentially missing authentication. Can you review the auth middleware and confirm whether these routes are actually protected?</blockquote>
  <p>Replit confirmed the routes were fully protected. The Replit Auth middleware was correctly applied. We marked it as verified in the report &mdash; false positive confirmed.</p>

  <h2>The result</h2>
  <div style="background:#E1F5EE;border:0.5px solid #1D9E75;border-radius:10px;padding:1rem;margin-bottom:1.5rem">
    <div style="font-weight:600;font-size:13px;color:#085041;margin-bottom:.35rem">&#x2705; Score B &mdash; properly secured</div>
    <div style="font-size:13px;color:#4a4846">Both genuine vulnerabilities fixed. False positive identified and verified. No features broken. Total time: under 1 hour.</div>
  </div>

  <h2>What this shows</h2>
  <p><strong>Working and secure are different things.</strong> Evident-AI worked perfectly before the scan. Users were logging in, documents were being processed. But two genuine vulnerabilities were sitting there quietly.</p>
  <p><strong>Not every finding is real.</strong> One of three critical findings was a false positive. Without the verify step &mdash; without asking Replit to investigate before acting &mdash; we might have tried to fix something that was not broken and actually caused a problem.</p>
  <p><strong>B is the right target.</strong> After fixing two genuine issues Evident-AI scored B. That is the realistic target for an AI-built app. B means properly secured for real users. A requires enterprise-level hardening that goes well beyond what any AI builder can automate.</p>

  <div style="background:#EEEDFE;border:0.5px solid #534AB7;border-radius:12px;padding:1.5rem;margin-top:2rem;text-align:center">
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">What score does your app get?</div>
    <div style="font-size:13px;color:#3C3489;margin-bottom:1rem">Free analysis. No login. Takes 2 minutes.</div>
    <a href="/" style="display:inline-block;font-size:14px;padding:10px 24px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none;font-weight:500">Run a free analysis &#8594;</a>
  </div>
</div>
</body>
</html>"""

POST_CSS = """
h2{font-size:19px;font-weight:700;margin:2.25rem 0 .75rem;line-height:1.35}
h3{font-size:16px;font-weight:700;margin:1.75rem 0 .5rem}
p{color:#4a4846;line-height:1.75;margin-bottom:1.1rem;font-size:16px}
ul,ol{color:#4a4846;line-height:1.75;margin:0 0 1.1rem 1.25rem;font-size:16px}
li{margin-bottom:.4rem}
strong{color:#1a1917;font-weight:600}
blockquote{border-left:3px solid #534AB7;padding:.85rem 1.15rem;margin:1.5rem 0;background:#EEEDFE;border-radius:0 8px 8px 0;font-size:15px;color:#3C3489;line-height:1.7}
blockquote p{color:#3C3489;margin-bottom:.6rem;font-size:15px}
blockquote p:last-child{margin-bottom:0}
table{width:100%;border-collapse:collapse;margin:1.5rem 0;font-size:14px}
th{text-align:left;padding:.6rem .75rem;border-bottom:1.5px solid #e8e6e0;font-weight:600}
td{padding:.6rem .75rem;border-bottom:0.5px solid #e8e6e0;color:#4a4846;vertical-align:top}
code{background:#EEEDFE;color:#3C3489;padding:1px 6px;border-radius:5px;font-size:13.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#1a1917;color:#e8e6e0;padding:1rem 1.15rem;border-radius:10px;overflow-x:auto;margin:1.5rem 0;font-size:13px;line-height:1.6}
pre code{background:none;color:inherit;padding:0;font-size:13px}
hr{border:none;border-top:0.5px solid #e8e6e0;margin:2.5rem 0}
a{color:#534AB7}
.cta{background:#EEEDFE;border:0.5px solid #534AB7;border-radius:10px;padding:1.25rem 1.5rem;margin-top:2.5rem;font-size:15px;line-height:1.7;color:#3C3489}
"""


def _externalise_links(html):
    """Open anything that leaves verilay.dev in a new tab.

    Catches the non-obvious case: a /blog/<slug> link looks internal, but if that
    post has a medium_url it renders as an immediate redirect, so the reader is
    silently thrown off-site mid-article. Those get treated as external too.

    Links to self-hosted posts stay in the same tab, which is what you want for
    ordinary same-site navigation. Anything already carrying a target= is left
    alone.
    """
    import re as _re_lk
    medium_slugs = {p["slug"] for p in BLOG_POSTS if p.get("medium_url")}

    def _fix(m):
        tag, href = m.group(0), m.group(1)
        if "target=" in tag:
            return tag
        leaves_site = href.startswith("http")
        if not leaves_site and href.startswith("/blog/"):
            leaves_site = href[len("/blog/"):].strip("/") in medium_slugs
        if not leaves_site:
            return tag
        return tag[:-1] + ' target="_blank" rel="noopener">'

    return _re_lk.sub(r'<a\s+href="([^"]+)"[^>]*>', _fix, html)


def render_post(post):
    """Render a self-hosted post from its `body` HTML.

    Generic on purpose. render_evident_case_study() is a one-off page with its own
    bespoke markup; everything written since is just a dict entry with a `body`,
    so adding a post never means adding a function.
    """
    bg, fg = CAT_COLORS.get(post.get("category", ""), ("#EEEDFE", "#3C3489"))
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + post["title"] + """ - Verilay</title>
<meta name="description" content=\"""" + post.get("excerpt", "").replace('"', "&quot;") + """\">
<link rel="canonical" href="https://verilay.dev/blog/""" + post["slug"] + """">
<meta property="og:title" content=\"""" + post["title"] + """\">
<meta property="og:description" content=\"""" + post.get("excerpt", "").replace('"', "&quot;") + """\">
<meta property="og:type" content="article">
<meta property="og:url" content="https://verilay.dev/blog/""" + post["slug"] + """">
<style>""" + BLOG_CSS + POST_CSS + """</style>
</head>
<body>
<nav>
  <a href="/" style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:17px;text-decoration:none;color:#1a1917">
    <svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg>
    Verilay
  </a>
  <a href="/blog" style="font-size:13px;color:#6b6966;text-decoration:none">&#8592; Blog</a>
</nav>
<div class="wrap" style="max-width:680px">
  <div style="margin-bottom:2rem">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:.75rem;flex-wrap:wrap">
      <span style="font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;background:""" + bg + """;color:""" + fg + """\">""" + post.get("category", "") + """</span>
      <span style="font-size:12px;color:#6b6966">""" + post.get("date", "") + """ &middot; """ + post.get("read_time", "") + """</span>
    </div>
    <h1 style="font-size:29px;font-weight:700;line-height:1.25;margin-bottom:1rem">""" + post["title"] + """</h1>
    <p style="font-size:17px;color:#6b6966;line-height:1.6">""" + post.get("excerpt", "") + """</p>
  </div>
  <hr>
""" + _externalise_links(post.get("body", "")) + """
  <div class="cta">
    <strong>Verilay is free at <a href="/">verilay.dev</a> &mdash; no account needed.</strong><br>
    Paste in a GitHub link, a ZIP from Lovable or Replit, or your live app&rsquo;s address, and
    it will tell you in plain English what your app is made of and what&rsquo;s worth worrying
    about. The code is public at
    <a href="https://github.com/ekbm/verilay" target="_blank" rel="noopener">github.com/ekbm/verilay</a>.
  </div>
</div>
</body>
</html>"""


@app.route("/blog/<slug>")
def blog_post(slug):
    post = next((p for p in BLOG_POSTS if p["slug"] == slug), None)
    if not post:
        return "Post not found", 404
    if slug == "evident-ai-c-to-b":
        return render_evident_case_study()
    # Self-hosted posts win over any Medium link. Medium is a distribution copy;
    # verilay.dev is the original, and should be the URL that gets indexed.
    if post.get("body"):
        return render_post(post)
    if post.get("medium_url"):
        return '<meta http-equiv="refresh" content="0;url=' + post["medium_url"] + '">'
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + post["title"] + """ - Verilay</title>
<style>""" + BLOG_CSS + """</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/blog" style="font-size:13px;color:#6b6966;text-decoration:none">Back to blog</a>
</nav>
<div class="wrap" style="max-width:680px">
  <div style="background:#EEEDFE;border:0.5px solid #534AB7;border-radius:10px;padding:1.5rem;text-align:center">
    <div style="font-size:24px;margin-bottom:.75rem">&#x270D;</div>
    <div style="font-weight:600;margin-bottom:.5rem">""" + post["title"] + """</div>
    <div style="font-size:13px;color:#6b6966">Coming soon. <a href="/" style="color:#534AB7">Run a free analysis</a> while you wait.</div>
  </div>
</div>
</body>
</html>"""


@app.route("/privacy")
def privacy():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy - Verilay</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
h2{font-size:17px;font-weight:600;margin:1.5rem 0 .5rem}
p{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px}
ul{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px;padding-left:1.25rem}
li{margin-bottom:.35rem}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">Last updated August 2026</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:.5rem">Privacy Policy</h1>
    <p>Verilay is a security analysis tool built by Moses Ekbote, free to use with an optional paid deep scan. This policy explains what we collect, why, and how you can delete it — for both the free tool and the paid tier.</p>
  </div>

  <h2>What we collect</h2>
  <ul>
    <li>The GitHub URL, live URL, or ZIP file you submit for analysis</li>
    <li>The analysis results — findings, score, and layer breakdown</li>
    <li>Your IP address for rate limiting (not stored permanently)</li>
    <li>If you join the waitlist — your email address</li>
    <li>If you rate a report — your thumbs up/down, and any comment or email you choose to add</li>
    <li>If you buy a deep scan or sign in — your email address, so we can identify your purchase and let you sign back in</li>
  </ul>

  <h2>What we do not collect</h2>
  <ul>
    <li>The free analysis needs no account — we don't know who you are unless you buy a deep scan or sign in</li>
    <li>No cookies or tracking beyond Plausible Analytics (privacy-friendly, no personal data)</li>
    <li>No payment card details — Stripe handles payment directly and Verilay never sees or stores your card number</li>
    <li>No access to your GitHub account beyond what you explicitly submit — we read public repos only via GitHub API, and never write to or modify any repository</li>
  </ul>

  <h2>How your data is stored</h2>
  <p>Analysis reports are stored in Supabase (hosted in the EU) linked to a random report ID. Reports are accessible only via your unique share link. We do not publish, share, or sell individual report data.</p>
  <p>Reports are kept so your share link keeps working and so we can improve the product. You can delete your report at any time using the Delete Report button on your report page, which removes the submitted code and findings.</p>

  <h2>Accounts and the deep scan</h2>
  <p>Signing in uses a passwordless email link or code — we never ask for or store a password. Buying a deep scan records your email, the app it was purchased for, the amount paid, and the purchase date; this comes from Stripe, which does not verify the email it collects, so a payment on its own does not sign you in. Signing in with that same email afterward links your purchase to an account so your reports are still there when you come back.</p>
  <p>Deep-scan reports are tied to your account rather than a share link alone, and are kept for as long as your account exists. You can request account and purchase-record deletion at any time by emailing <a href="mailto:moses@verilay.dev" style="color:#534AB7">moses@verilay.dev</a> — note that Stripe keeps its own transaction records independently, for tax and accounting purposes, which we cannot delete on your behalf.</p>

  <h2>Statistics</h2>
  <p>We track aggregate statistics — total analyses run, score distribution (how many A/B/C/D/F grades), and analysis method. This data is anonymised and used to improve the product.</p>

  <h2>Waitlist emails</h2>
  <p>If you join the waitlist, your email is stored in Supabase and used only to notify you when new features launch. You can request deletion by emailing moses@verilay.dev.</p>

  <h2>Feedback</h2>
  <p>If you rate a report and choose to leave a comment or email, these are stored with that report in Supabase. Email is optional and used only to follow up about the feedback you left — for example to let you know an issue was fixed. You can request deletion by emailing moses@verilay.dev.</p>

  <h2>Your rights</h2>
  <ul>
    <li>Delete your report anytime using the Delete Report button</li>
    <li>Request deletion of your account, purchase record, waitlist entry, or feedback email at moses@verilay.dev</li>
    <li>If you've never signed in or paid, there's no account data to delete — the free tool remains fully anonymous</li>
  </ul>

  <h2>Contact</h2>
  <p>Questions about privacy: <a href="mailto:moses@verilay.dev" style="color:#534AB7">moses@verilay.dev</a></p>

  <div style="margin-top:2.5rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <a href="/" style="display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
</body>
</html>"""


@app.route("/terms")
def terms():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms of Use - Verilay</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
h2{font-size:17px;font-weight:600;margin:1.5rem 0 .5rem}
p{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px}
ul{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px;padding-left:1.25rem}
li{margin-bottom:.35rem}
.highlight{background:#EEEDFE;border:0.5px solid #534AB7;border-radius:8px;padding:1rem;margin:1rem 0;font-size:13px;color:#3C3489}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">Last updated August 2026</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:.5rem">Terms of Use</h1>
    <p>By using Verilay you agree to these terms. If you do not agree, please do not use the service.</p>
  </div>

  <div class="highlight">
    <strong>Plain English summary:</strong> Verilay is an AI-powered security analysis tool, free to use, with an optional paid deep scan. It gives you information to help you understand your app — not professional security advice. Use findings as a starting point, not as a definitive security audit. Always verify with your AI builder before making changes.
  </div>

  <h2>1. What Verilay is</h2>
  <p>Verilay is an online tool that uses AI to analyse code repositories and provide plain-English security observations. It is designed to help non-developers understand potential security concerns in AI-built applications. The free analysis reads a sample of your files; the deep scan reads more of your codebase and checks every dependency in full detail.</p>

  <h2>2. Payment and the deep scan</h2>
  <p>The free analysis remains free for everyone, indefinitely, with no account required. The deep scan is a one-off paid upgrade for a single app: it reads more of your codebase, checks every dependency in full detail, and includes unlimited re-scans of that same app for 30 days from purchase so you can confirm a fix actually worked.</p>
  <ul>
    <li>Payment is processed by Stripe. Verilay never sees or stores your card details.</li>
    <li>Prices are shown in AUD at checkout before you pay.</li>
    <li>A deep scan is tied to the specific app (GitHub repository) it was purchased for.</li>
    <li><strong>Refunds:</strong> if a deep scan fails to run or produces no usable report, contact <a href="mailto:moses@verilay.dev" style="color:#534AB7">moses@verilay.dev</a> for a full refund. Once a report has been generated, the purchase has delivered what it promised, and refunds are at our discretion — reach out and we'll look at it fairly.</li>
  </ul>

  <h2>3. What Verilay is not</h2>
  <ul>
    <li>Not a professional security audit or penetration test</li>
    <li>Not a guarantee that your app is secure or insecure</li>
    <li>Not a substitute for professional security advice for production applications handling sensitive data</li>
    <li>Not liable for decisions made based on analysis results</li>
  </ul>

  <h2>4. AI disclaimer</h2>
  <p>Verilay uses Claude AI (Anthropic) to analyse code. AI analysis has known limitations:</p>
  <ul>
    <li><strong>False positives:</strong> Verilay may flag correct code as a potential issue</li>
    <li><strong>False negatives:</strong> Verilay may miss genuine security issues</li>
    <li><strong>Context limitations:</strong> Analysis is based on a sample of files — not the entire codebase, even for the deep scan</li>
    <li><strong>Score variation:</strong> The same codebase may receive slightly different scores on different runs</li>
    <li><strong>Not a replacement for human review:</strong> For apps handling payments, health data, or personal information, a professional security review is recommended</li>
  </ul>
  <p>Always verify findings with your AI builder before making any code changes. Verilay provides advice prompts specifically designed for safe investigation before action.</p>

  <h2>5. Acceptable use</h2>
  <p>You may use Verilay to analyse:</p>
  <ul>
    <li>Your own applications and repositories</li>
    <li>Open source repositories you have permission to analyse</li>
    <li>Applications you have been authorised to assess</li>
  </ul>
  <p>You may not use Verilay to:</p>
  <ul>
    <li>Analyse applications without authorisation from the owner</li>
    <li>Attempt to extract, scrape, or copy the analysis prompts or AI logic</li>
    <li>Deliberately submit malicious inputs to probe or attack the service</li>
    <li>Resell or commercially embed Verilay without a commercial licence</li>
    <li>Share a paid account's sign-in access with someone who did not make the purchase</li>
  </ul>

  <h2>6. Intellectual property</h2>
  <p>Verilay is built and owned by Moses Ekbote. The source code is available on GitHub under a custom licence. Commercial use requires a separate licence — contact moses@verilay.dev.</p>

  <h2>7. No warranty</h2>
  <p>Verilay is provided "as is" without warranty of any kind. We make no guarantees about the accuracy, completeness, or reliability of analysis results. Use at your own risk.</p>

  <h2>8. Limitation of liability</h2>
  <p>To the maximum extent permitted by law, Verilay and its creator shall not be liable for any damages arising from use of the service, including but not limited to security breaches, data loss, or decisions made based on analysis results. Our total liability for any claim relating to the deep scan is limited to the amount you paid for that scan.</p>

  <h2>9. Changes to terms</h2>
  <p>These terms may be updated from time to time. Continued use of Verilay constitutes acceptance of the updated terms.</p>

  <h2>10. Contact</h2>
  <p>Questions: <a href="mailto:moses@verilay.dev" style="color:#534AB7">moses@verilay.dev</a></p>

  <div style="margin-top:2.5rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <a href="/" style="display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
</body>
</html>"""


@app.route("/about")
def about():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>About - Verilay</title>
<meta name="description" content="Verilay was built by Moses Ekbote — a non-developer who built real apps and needed to know if they were secure.">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
p{color:#4a4846;line-height:1.7;margin-bottom:1rem;font-size:15px}
.card{background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1.25rem;margin-bottom:.75rem}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">Our story</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:1rem">Built by a non-developer, for non-developers</h1>
  </div>

  <div style="background:#EEEDFE;border:0.5px solid #534AB7;border-radius:12px;padding:1.5rem;margin-bottom:2rem;display:flex;gap:1rem;align-items:flex-start">
    <div style="font-size:32px;flex-shrink:0">👋</div>
    <div>
      <div style="font-weight:700;font-size:16px;margin-bottom:.25rem">Moses Ekbote</div>
      <div style="font-size:13px;color:#4a4846;line-height:1.6;margin-bottom:.5rem">I build things in my spare time. Verilay, Evident, LogInsight, and BuildStory are all live products built without a traditional development background.</div>
      <div style="font-size:13px;color:#4a4846;line-height:1.6;margin-bottom:.75rem">Follow the journey on <a href="https://medium.com/@mosesekbote" target="_blank" style="color:#534AB7">Medium</a>.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <a href="https://medium.com/@mosesekbote" target="_blank" style="font-size:11px;padding:3px 10px;background:#fff;border:0.5px solid #534AB7;border-radius:20px;color:#534AB7;text-decoration:none">Medium</a>
        <a href="https://github.com/ekbm" target="_blank" style="font-size:11px;padding:3px 10px;background:#fff;border:0.5px solid #534AB7;border-radius:20px;color:#534AB7;text-decoration:none">GitHub</a>
      </div>
    </div>
  </div>

  <h2 style="font-size:18px;font-weight:700;margin-bottom:.75rem">Other products</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:2rem">
    <a href="https://evident-ai.net" target="_blank" style="display:block;text-decoration:none;background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem;transition:box-shadow .15s" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,.07)'" onmouseout="this.style.boxShadow='none'">
      <div style="font-weight:600;font-size:14px;color:#1a1917;margin-bottom:.25rem">Evident AI &#x2197;</div>
      <div style="font-size:12px;color:#6b6966;line-height:1.5">AI-powered study and document management platform. Built on Replit with PostgreSQL and OpenAI.</div>
    </a>

    <a href="https://buildstory.com.au" target="_blank" style="display:block;text-decoration:none;background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem;transition:box-shadow .15s" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,.07)'" onmouseout="this.style.boxShadow='none'">
      <div style="font-weight:600;font-size:14px;color:#1a1917;margin-bottom:.25rem">BuildStory &#x2197;</div>
      <div style="font-size:12px;color:#6b6966;line-height:1.5">Document your build journey. Track what you built, why, and what you learned along the way.</div>
    </a>
    <a href="https://loginsight.app" target="_blank" style="display:block;text-decoration:none;background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1rem;transition:box-shadow .15s" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,.07)'" onmouseout="this.style.boxShadow='none'">
      <div style="font-weight:600;font-size:14px;color:#1a1917;margin-bottom:.25rem">LogInsight &#x2197;</div>
      <div style="font-size:12px;color:#6b6966;line-height:1.5">Log analysis and environment monitoring tool. Plain-English explanations for complex server logs.</div>
    </a>
    <a href="https://verilay.dev" style="display:block;text-decoration:none;background:#EEEDFE;border:0.5px solid #534AB7;border-radius:10px;padding:1rem">
      <div style="font-weight:600;font-size:14px;color:#534AB7;margin-bottom:.25rem">Verilay &#x2713; You are here</div>
      <div style="font-size:12px;color:#3C3489;line-height:1.5">Free security analysis for AI-built apps. Plain-English findings and advice prompts.</div>
    </a>
  </div>

  <h2 style="font-size:18px;font-weight:700;margin-bottom:.75rem">Why Verilay exists</h2>
  <p>I built several apps using AI platforms — Evident, LogInsight, BuildStory. Real apps with real users, databases, payments, and login systems.</p>
  <p>One day I ran a security scan and found my database was publicly accessible. No authentication. Anyone with the URL could download everything.</p>
  <p>I went looking for tools to check my other apps. What I found were security scanners written for developers — full of terms like "JWT verification bypass" and "insufficient input sanitization." I understood the words but not the sentences. I had no idea what to actually do.</p>
  <p>So I built what I wished existed: a tool that reads your code and explains what it found in plain English — then helps you investigate safely with your AI builder before touching anything.</p>

  <h2 style="font-size:18px;font-weight:700;margin:.75rem 0 .75rem">The philosophy</h2>
  <div class="card">
    <div style="font-weight:600;margin-bottom:.35rem">&#x1F4AC; Advise, don't fix</div>
    <div style="font-size:13px;color:#4a4846;line-height:1.6">Every prompt Verilay generates asks your AI builder to investigate and advise — never to make sweeping changes. Blindly applying fix prompts can break working code.</div>
  </div>
  <div class="card">
    <div style="font-weight:600;margin-bottom:.35rem">&#x2705; Verify before acting</div>
    <div style="font-size:13px;color:#4a4846;line-height:1.6">Verilay lets you paste your builder's response back and update the report. The score reflects what's actually been verified — not just what static analysis found.</div>
  </div>
  <div class="card">
    <div style="font-weight:600;margin-bottom:.35rem">&#x1F3AF; B grade is the realistic target</div>
    <div style="font-size:13px;color:#4a4846;line-height:1.6">Not A. For AI-built apps, B means properly secured for real users. A requires enterprise-level hardening beyond what any AI builder can automate.</div>
  </div>
  <div class="card">
    <div style="font-weight:600;margin-bottom:.35rem">&#x1F513; Free forever for non-developers</div>
    <div style="font-size:13px;color:#4a4846;line-height:1.6">Verilay will always be free to analyse your app. No login required. Pro features for power users coming soon.</div>
  </div>

  <h2 style="font-size:18px;font-weight:700;margin:.75rem 0 .75rem">Built with</h2>
  <p style="font-size:13px">Python / Flask &nbsp;&middot;&nbsp; Claude AI (Anthropic) &nbsp;&middot;&nbsp; Supabase &nbsp;&middot;&nbsp; Railway &nbsp;&middot;&nbsp; Cloudflare</p>
  <p style="font-size:13px">Source code: <a href="https://github.com/ekbm/verilay" target="_blank" style="color:#534AB7">github.com/ekbm/verilay</a></p>

  <h2 style="font-size:18px;font-weight:700;margin:.75rem 0 .75rem">Get in touch</h2>
  <div style="background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1.25rem;margin-bottom:.75rem">
    <div style="font-weight:600;margin-bottom:.35rem">&#x2709; General enquiries &amp; feedback</div>
    <div style="font-size:13px;color:#6b6966;margin-bottom:.5rem">Questions about Verilay, feature requests, or want to share what score your app got?</div>
    <a href="mailto:moses@verilay.dev?subject=Verilay%20Enquiry" style="font-size:13px;color:#534AB7">moses@verilay.dev</a>
  </div>
  <div style="background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1.25rem;margin-bottom:.75rem">
    <div style="font-weight:600;margin-bottom:.35rem">&#x1F4BC; Commercial licensing</div>
    <div style="font-size:13px;color:#6b6966;margin-bottom:.5rem">Want to embed Verilay in your product or offer it to your customers?</div>
    <a href="mailto:moses@verilay.dev?subject=Verilay%20Commercial%20Licence" style="font-size:13px;color:#534AB7">moses@verilay.dev</a>
  </div>
  <div style="background:#fff;border:0.5px solid #e8e6e0;border-radius:10px;padding:1.25rem">
    <div style="font-weight:600;margin-bottom:.35rem">&#x1F4F0; Follow the journey</div>
    <div style="font-size:13px;color:#6b6966;margin-bottom:.5rem">Building in public on Medium — new posts as features ship.</div>
    <a href="https://medium.com/@mosesekbote" target="_blank" style="font-size:13px;color:#534AB7">medium.com/@mosesekbote</a>
  </div>

  <div style="margin-top:2.5rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <a href="/" style="display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
</body>
</html>"""


@app.route("/ai-disclaimer")
def ai_disclaimer():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Disclaimer - Verilay</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
h2{font-size:17px;font-weight:600;margin:1.5rem 0 .5rem}
p{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px}
ul{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px;padding-left:1.25rem}
li{margin-bottom:.4rem}
.good{background:#E1F5EE;border:0.5px solid #1D9E75;border-radius:8px;padding:1rem;margin:.5rem 0}
.warn{background:#FEF9C3;border:0.5px solid #EF9F27;border-radius:8px;padding:1rem;margin:.5rem 0}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">Transparency</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:.5rem">AI Disclaimer</h1>
    <p>Verilay uses AI to analyse code. Here is exactly what that means — the good and the limitations.</p>
  </div>

  <h2>What AI Verilay uses</h2>
  <p>Verilay uses <strong>Claude</strong>, built by <a href="https://anthropic.com" target="_blank" style="color:#534AB7">Anthropic</a> — one of the leading AI safety companies. Claude reads your code files and generates security findings, plain-English explanations, and advice prompts.</p>

  <h2>What AI does well here</h2>
  <div class="good">
    <ul style="list-style:none;padding:0">
      <li>&#x2705; Reads code and explains what it does in plain English</li>
      <li>&#x2705; Identifies common security patterns and anti-patterns</li>
      <li>&#x2705; Understands platform-specific patterns (Supabase, Replit, Firebase, Lovable)</li>
      <li>&#x2705; Generates safe investigative prompts tailored to your specific codebase</li>
      <li>&#x2705; Explains findings at different levels — technical and plain English</li>
    </ul>
  </div>

  <h2>Known limitations</h2>
  <div class="warn">
    <ul style="list-style:none;padding:0">
      <li>&#x26A0;&#xFE0F; <strong>False positives</strong> — may flag correct code as a potential issue</li>
      <li>&#x26A0;&#xFE0F; <strong>False negatives</strong> — may miss genuine security issues</li>
      <li>&#x26A0;&#xFE0F; <strong>File sample only</strong> — analyses up to 25 files, not your entire codebase</li>
      <li>&#x26A0;&#xFE0F; <strong>Score variation</strong> — same codebase may score slightly differently on different runs</li>
      <li>&#x26A0;&#xFE0F; <strong>No code execution</strong> — reads code statically, cannot test actual runtime behaviour</li>
      <li>&#x26A0;&#xFE0F; <strong>Not a penetration test</strong> — does not attempt to exploit vulnerabilities</li>
    </ul>
  </div>

  <h2>How we reduce AI errors</h2>
  <p>Verilay includes extensive platform awareness rules — over 30 patterns that tell Claude what correct behaviour looks like for Lovable, Replit, Supabase, Firebase, Drizzle, NextAuth, Clerk, and more. These rules are updated continuously based on real-world false positives reported by users.</p>
  <p>The verify feature lets you confirm findings with your AI builder and update the report — so the score reflects verified reality, not just static analysis.</p>

  <h2>When to get a professional review</h2>
  <p>Verilay is a first-pass overview. For apps that handle:</p>
  <ul>
    <li>Medical or health data</li>
    <li>Financial transactions or payment card data</li>
    <li>Personal data covered by GDPR or similar regulations</li>
    <li>Authentication for enterprise or B2B customers</li>
  </ul>
  <p>We recommend a professional security review in addition to Verilay. Services like <a href="https://snyk.io" target="_blank" style="color:#534AB7">Snyk</a> and <a href="https://codrabbit.ai" target="_blank" style="color:#534AB7">CodeRabbit</a> provide deeper analysis.</p>

  <h2>Anthropic responsible AI</h2>
  <p>Claude is built by Anthropic with a focus on AI safety and responsible deployment. Learn more at <a href="https://anthropic.com/responsible-scaling-policy" target="_blank" style="color:#534AB7">anthropic.com</a>.</p>

  <div style="margin-top:2.5rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <a href="/" style="display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
</body>
</html>"""


@app.route("/changelog")
def changelog():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Changelog - Verilay</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
.entry{border-left:2px solid #e8e6e0;padding-left:1.25rem;margin-bottom:2rem;position:relative}
.entry::before{content:"";width:10px;height:10px;background:#534AB7;border-radius:50%;position:absolute;left:-6px;top:4px}
.tag{display:inline-block;font-size:10px;font-weight:600;padding:2px 8px;border-radius:20px;margin-right:4px;margin-bottom:4px}
.new{background:#E1F5EE;color:#085041}
.fix{background:#FCEBEB;color:#A32D2D}
.improve{background:#EFF6FF;color:#1D4ED8}
.feature{background:#EEEDFE;color:#3C3489}
</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917"><svg width="24" height="24" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg> <span style="font-weight:700;font-size:17px;color:#1a1917">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:2rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">What's new</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:.5rem">Changelog</h1>
    <p style="color:#6b6966;font-size:14px">Every improvement, fix and new feature — in plain English.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 18, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">More specific recommended fixes</div>
    <div><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">The Recommended Fixes and Second Opinion sections now reference your actual findings rather than just a summary — more useful, specific guidance instead of one generic suggestion.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 18, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Score could look different mid-analysis than in your saved report</div>
    <div><span class="tag fix">Fix</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">In some cases the critical/warning counts shown while your analysis was still running didn't match what got saved to your report afterward. Both now always agree.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 18, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Dependency vulnerability count is now accurate</div>
    <div><span class="tag fix">Fix</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">A vulnerability that's catalogued under two different public reference numbers was being counted twice, making the total look worse than it really is. Each one is now counted once.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 18, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Checks your dependencies for known security problems</div>
    <div><span class="tag new">New</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Every scan — including the free one — now checks the code libraries your app depends on against OSV.dev, a public database of documented security vulnerabilities. If something's affected, you'll see how many issues were found.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 18, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Saved reports now show your full security findings</div>
    <div><span class="tag fix">Fix</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Reopening a report you'd saved or shared previously left out the exposed-keys check, even though it had run. It now shows up properly whenever you come back to a report, not just the moment it first finishes.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">August 9, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">See what your app is made of</div>
    <div><span class="tag improve">New</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Reports now include a plain-English breakdown of your whole app — grouping every file into simple categories like visual pages, data &amp; logins, settings and building blocks. It shows that most of an app is safe internal machinery, and that the parts which matter for security are a smaller set — the ones Verilay checks first. There's a simple view for non-developers and a developer view for more technical detail.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 21, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Reads much more of your code</div>
    <div><span class="tag fix">Fix</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Verilay now reads far more of each file before grading. Previously, large single-file apps could be cut short, so the scan sometimes only saw the styling and missed the JavaScript or backend logic further down — occasionally misreading a working app as an incomplete one. Your scans now take in much more of the actual code, so the analysis is based on what your app really does.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 16, 2026</div>
    <div><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Re-running the same app now gives you the same grade. Your score is calculated directly from the findings, so the headline grade and verdict always match the detailed results below them.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 16, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">See exactly what was analysed</div>
    <div><span class="tag new">New</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Every report now shows how many of your files were analysed, with the full list a click away — so you always know precisely what the scan covered.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 16, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Clearer guidance on every finding</div>
    <div><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Every critical issue now gets its own advice prompt, with the most important issues listed first — so you always know what to tackle, and in what order.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 14, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Minified production code no longer flagged</div>
    <div><span class="tag fix">Fix</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Verilay no longer treats minified or bundled JavaScript as a problem. Shipping minified code is how every production app is built — it's a sign things are working, not a security risk. It will never lower your score or show as a warning again.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 10, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Blog, Privacy, Terms and About pages</div>
    <div><span class="tag new">New</span><span class="tag new">New</span><span class="tag new">New</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Added Blog at /blog, Privacy policy, Terms of use with AI disclaimer, About page with the story behind Verilay, and this Changelog. Verilay now feels like a proper product.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 9, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Advice-first prompts — investigate before fixing</div>
    <div><span class="tag feature">Feature</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">All fix prompts changed to advice prompts. Every prompt now asks your AI builder to investigate and advise before making any changes. "Copy fix prompt" became "Get advice prompt". "Fix in Lovable" became "Ask Lovable about this". Safety warning added before copying.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 9, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Verify findings with your AI builder</div>
    <div><span class="tag feature">Feature</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Mark any finding as verified by pasting your AI builder's response. Score recalculates based on unverified findings only. Layer dots turn green when all findings are verified. Report becomes a living document.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 8, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Smart file selection + dependency awareness</div>
    <div><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Verilay now reads package.json first to identify your exact stack before analysing. Files are selected by security relevance not just filename. Added awareness for Drizzle ORM, NextAuth, Clerk, Prisma, Flask, Gunicorn and more.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 7, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Waitlist capture + score A/B/C guide</div>
    <div><span class="tag new">New</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Waitlist popup after 3 analyses to capture demand for Pro features. Score guide now shows exactly what's needed to reach each grade — including a checklist to go from B to A.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">June 5, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Learner mode + unique app-specific analogies</div>
    <div><span class="tag new">New</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Learner mode explains each layer in plain English with analogies specific to your app. A travel app gets travel analogies. A legal app gets legal analogies. Never generic "think of it like a bouncer" explanations.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">May 28, 2026</div>
    <div style="font-weight:700;font-size:16px;margin-bottom:.5rem">Platform awareness for Lovable, Replit, Supabase</div>
    <div><span class="tag fix">Fix</span><span class="tag improve">Improve</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">Added 30+ platform-specific rules to prevent false positives. Supabase anon keys, Replit OIDC auth, Lovable auto-managed env vars and TanStack Query patterns are now correctly recognised as valid — never flagged.</p>
  </div>

  <div class="entry">
    <div style="font-size:12px;color:#6b6966;margin-bottom:.35rem">May 20, 2026</div>
    <div style="font-weight:700;font-size=16px;margin-bottom:.5rem">&#x1F680; Verilay launched</div>
    <div><span class="tag new">New</span></div>
    <p style="font-size:13px;color:#4a4846;margin-top:.5rem">First public release. GitHub and URL analysis, plain-English security reports, layer map with Expert and Learner modes. Free, no login required.</p>
  </div>

  <div style="margin-top:2.5rem;padding-top:1.5rem;border-top:0.5px solid #e8e6e0;text-align:center">
    <a href="/" style="display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff;border-radius:20px;text-decoration:none">Run a free analysis</a>
  </div>
</div>
</body>
</html>"""


@app.route("/sitemap.xml")
def sitemap():
    """Sitemap for search engine indexing.

    Lists only pages that actually hold content here. Posts whose `medium_url` is
    set render as a redirect to Medium, so submitting those would point search
    engines at an empty page and hand the ranking to medium.com. Self-hosted
    posts — the ones with a `body` — are the ones worth indexing.
    """
    urls = [
        ("https://verilay.dev/", "weekly", "1.0"),
        ("https://verilay.dev/blog", "weekly", "0.8"),
        ("https://verilay.dev/about", "monthly", "0.5"),
    ]
    for p in BLOG_POSTS:
        if p.get("body") or p["slug"] == "evident-ai-c-to-b":
            urls.append(("https://verilay.dev/blog/" + p["slug"], "monthly", "0.7"))

    body = "".join(
        "\n  <url>\n    <loc>" + loc + "</loc>\n    <changefreq>" + freq +
        "</changefreq>\n    <priority>" + pri + "</priority>\n  </url>"
        for loc, freq, pri in urls
    )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           + body + "\n</urlset>")
    return app.response_class(xml, mimetype='application/xml')


@app.route("/robots.txt")
def robots():
    """Robots.txt for search engines."""
    txt = """User-agent: *
Allow: /
Sitemap: https://verilay.dev/sitemap.xml"""
    return app.response_class(txt, mimetype='text/plain')


@app.route("/counter")
def counter_debug():
    """Debug endpoint to check counter sources."""
    mem = 0  # memory count deprecated — using Supabase stats table
    supabase_count = 0
    if _HAS_SUPABASE:
        try:
            result = _sb.table("reports").select("id", count="exact").execute()
            supabase_count = result.count or 0
        except:
            pass
    return jsonify({"memory": mem, "supabase_rows": supabase_count})


@app.route("/save-report", methods=["POST"])
def save_report_route():
    try:
        data = request.get_json()
        existing_id = data.pop("report_id", None)
        if existing_id and _HAS_SUPABASE:
            try:
                _sb.table("reports").update({"data": data}).eq("id", existing_id).execute()
                return jsonify({"report_id": existing_id})
            except:
                pass
        report_id = save_report_data(data)
        return jsonify({"report_id": report_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


COLLAPSE_THRESHOLD = 5  # long lists (e.g. 13 dependency CVEs) start collapsed


def _collapsible(items_html, count):
    """Native <details>/<summary> — no JS needed on this static page. Open by
    default under the threshold (a couple of findings are worth seeing right
    away); collapsed by default above it, so a long dependency list doesn't
    push everything else off the first screen."""
    if count <= COLLAPSE_THRESHOLD:
        return items_html
    return (
        f'<details><summary style="cursor:pointer;font-size:13px;color:#534AB7;'
        f'font-weight:600;padding:.25rem 0">Show all {count} &darr;</summary>'
        f'<div style="margin-top:.5rem">{items_html}</div></details>'
    )


@app.route("/report/<report_id>")
def view_report(report_id):
    data = get_report_data(report_id)
    if not data:
        return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Verilay - Not Found</title>
<meta http-equiv="refresh" content="5;url=https://verilay.dev">
</head><body style="font-family:-apple-system,sans-serif;padding:3rem;max-width:500px;margin:0 auto">
<div style="font-size:24px;color:#534AB7">&#10005; Verilay</div>
<h2>Report not found</h2>
<p style="color:#666;margin:1rem 0">This report has expired or was cleared.</p>
<a href="https://verilay.dev" style="background:#534AB7;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">
Run a new analysis &rarr;</a>
<p style="color:#aaa;font-size:12px;margin-top:1rem">Redirecting in 5 seconds...</p>
</body></html>""", 404

    h = data.get("health", {})
    pr = data.get("prod_ready", {})
    stack = data.get("stack", [])
    layers = data.get("layers", [])
    fixes = data.get("top_fixes", [])
    so = data.get("second_opinion", {})

    is_preview = bool(data.get("preview_only")) or h.get("score") is None
    if is_preview:
        verdict_label = "Preview — not graded"
        verdict_color = "#6b6966"
        verdict_reason = "A URL scan only sees what the site serves to a browser, not your source code. Scan your GitHub repo or upload a ZIP for a real review."
        score_display = "n/a"
        score_color = "#999"
    else:
        verdict_label, verdict_color, verdict_reason = verdict_from_score(h.get("score", "C"))
        score_color = {"A":"#1D9E75","B":"#4A90D9","C":"#EF9F27","D":"#E24B4A","F":"#A32D2D"}.get(h.get("score","?"),"#999")
        score_display = h.get("score","?")
    sev_bg = {"critical":"#FCEBEB","warning":"#FEF3C7","passing":"#EAF3DE"}
    sev_tc = {"critical":"#A32D2D","warning":"#92400E","passing":"#27500A"}

    out = []
    out.append(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verilay — {data.get('repo','Report')}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8fc;color:#1a1a2e;font-size:15px;line-height:1.6}}
.wrap{{max-width:860px;margin:0 auto;padding:2rem 1.5rem}}
.header{{background:#534AB7;color:#fff;padding:1rem 1.5rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}}
.header a{{color:#fff;opacity:.8;font-size:13px;text-decoration:none}}
.card{{background:#fff;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1rem;border:0.5px solid #e5e5f0}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:1rem}}
.sb{{background:#f8f8fc;border-radius:8px;padding:.75rem;text-align:center}}
.sn{{font-size:28px;font-weight:700}}
.sl{{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em}}
.st{{font-size:11px;font-weight:600;color:#888;letter-spacing:.06em;text-transform:uppercase;margin:1.5rem 0 .65rem}}
.tag{{display:inline-block;background:#EEEDFE;color:#3C3489;font-size:12px;padding:3px 10px;border-radius:20px;margin:2px}}
.layer{{background:#fff;border-radius:10px;padding:1rem;margin-bottom:8px;border:0.5px solid #e5e5f0}}
.finding{{border-radius:8px;padding:.65rem .85rem;margin-bottom:6px;font-size:13px}}
.fix{{background:#f8f8fc;border-radius:10px;padding:1rem;margin-bottom:8px;border-left:3px solid #534AB7}}
.pb{{background:#f0f0f8;border-radius:8px;padding:.65rem .85rem;font-size:12px;font-family:monospace;margin-top:.5rem;white-space:pre-wrap;word-break:break-word}}
.footer{{text-align:center;padding:2rem;font-size:12px;color:#aaa}}
@media(max-width:600px){{.wrap{{padding:1rem}}}}
</style></head>
<body>
<div class="header">
  <div style="display:flex;align-items:center;gap:10px">
    <svg width="28" height="28" viewBox="0 0 400 400"><rect width="400" height="400" rx="72" fill="#fff" fill-opacity=".2"/>
    <polyline points="148,108 200,208 252,108" fill="none" stroke="#fff" stroke-width="32" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <span style="font-size:18px;font-weight:600">Verilay Report</span>
  </div>
  <a href="https://verilay.dev">Analyse your own app &rarr;</a>
</div>
<div class="wrap">""")

    # Summary card
    out.append(f"""<div class="card">
  <div style="font-size:20px;font-weight:700;margin-bottom:.25rem">{data.get('repo','')}</div>
  <div style="font-size:13px;color:#666;margin-bottom:.65rem">{data.get('summary','')}</div>
  <div style="display:inline-block;background:{verdict_color};color:#fff;padding:5px 14px;border-radius:20px;font-size:13px;font-weight:500;margin-bottom:.5rem">{verdict_label}</div>
  <div style="font-size:13px;color:#555">{verdict_reason}</div>
</div>""")

    # Score grid
    out.append(f"""<div class="sg">
  <div class="sb"><div class="sn" style="color:{score_color}">{score_display}</div><div class="sl">Score</div></div>
  <div class="sb"><div class="sn" style="color:#E24B4A">{h.get('critical',0)}</div><div class="sl">Critical</div></div>
  <div class="sb"><div class="sn" style="color:#EF9F27">{h.get('warnings',0)}</div><div class="sl">Warnings</div></div>
  <div class="sb"><div class="sn" style="color:#1D9E75">{h.get('passing',0)}</div><div class="sl">Passing</div></div>
</div>""")

    # Stack
    if stack:
        tags = "".join(f'<span class="tag">{s.get("name","")} {s.get("version","")}</span>' for s in stack)
        out.append(f'<div class="st">Tech Stack</div><div class="card">{tags}</div>')

    # Verified findings — the deterministic secret scan. Always full detail,
    # free or paid: this check has been free for everyone since it shipped.
    scan = data.get("secret_scan") or {}
    if scan.get("files_scanned"):
        scan_findings = scan.get("findings", [])
        if not scan_findings:
            out.append(
                '<div class="card"><strong style="color:#1D9E75">✓ No exposed keys or passwords found</strong>'
                f'<div style="font-size:13px;color:#666;margin-top:.35rem">All {scan["files_scanned"]} files '
                'were checked for hardcoded API keys, passwords and database logins. This check reads every '
                'file directly — it is not a sample.</div></div>'
            )
        else:
            items = "".join(
                f'<div class="finding" style="background:{sev_bg.get(f2.get("severity","warning"),"#FEF3C7")};'
                f'color:{sev_tc.get(f2.get("severity","warning"),"#92400E")}">'
                f'<strong>{f2.get("name","")}</strong> — {f2.get("file","")} line {f2.get("line","")}'
                f'<div style="margin-top:.25rem">{f2.get("plain","")}</div></div>'
                for f2 in scan_findings
            )
            out.append(f'<div class="st">Verified Findings</div><div class="card">'
                       f'{_collapsible(items, len(scan_findings))}</div>')

    # Dependency check (OSV.dev). Full package/CVE detail only appears here
    # when it was saved — the free scan's teaser shape (count only) never
    # carries a "vulnerabilities" list, so this naturally shows less for a
    # free report without branching on anything deep-scan specific.
    osv = data.get("osv_scan") or {}
    if osv.get("packages_checked"):
        vulns = osv.get("vulnerabilities")  # present only on full-detail (paid) reports
        found = osv.get("vulnerabilities_found", len(vulns) if vulns is not None else 0)
        noun = "dependency" if osv["packages_checked"] == 1 else "dependencies"
        if not found:
            out.append(
                f'<div class="card"><strong style="color:#1D9E75">✓ All {osv["packages_checked"]} {noun} '
                f'checked — none vulnerable</strong><div style="font-size:13px;color:#666;margin-top:.35rem">'
                'Checked against OSV.dev, a public database of known security vulnerabilities.</div></div>'
            )
        elif vulns is not None:
            items = "".join(
                f'<div class="finding" style="background:{sev_bg.get("critical" if v.get("severity") in ("critical","high") else "warning","#FCEBEB")};'
                f'color:{sev_tc.get("critical" if v.get("severity") in ("critical","high") else "warning","#A32D2D")}">'
                f'<strong>{v.get("package","")}@{v.get("version_found","")}</strong> — {v.get("id","")}'
                f'<div style="margin-top:.25rem">{v.get("summary","")}</div>'
                + (f'<div style="margin-top:.25rem"><strong>Fix:</strong> update to {v["fixed_version"]}</div>'
                   if v.get("fixed_version") else "")
                + '</div>'
                for v in vulns
            )
            out.append(f'<div class="st">Dependency Vulnerabilities</div><div class="card">'
                       f'{_collapsible(items, len(vulns))}</div>')
        else:
            out.append(
                f'<div class="card"><strong style="color:#EF9F27">{found} {"dependency has" if found==1 else "dependencies have"} '
                f'known vulnerabilities</strong><div style="font-size:13px;color:#666;margin-top:.35rem">'
                f'Checked {osv["packages_checked"]} {noun} against OSV.dev.</div></div>'
            )

    # Ask AI button
    import urllib.parse as _urlparse
    _critical = [f'{l.get("name")}: {f2.get("title","")}' for l in layers for f2 in l.get("expert",{}).get("findings",[]) if f2.get("severity") in ["critical","warning"]]
    _ask_q = f"I ran Verilay on {data.get('repo','my app')} (Score {h.get('score','?')}) and got these issues:\n" + ("\n".join(_critical[:5]) or "No critical issues") + "\n\nExplain these simply and how to fix them. I am not a developer."
    _ask_url = "https://claude.ai/new?q=" + _urlparse.quote(_ask_q)
    out.append(f'<div style="margin:.75rem 0;padding:.85rem 1rem;background:#EEEDFE;border:0.5px solid #534AB7;border-radius:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px"><div><div style="font-size:13px;font-weight:600;color:#3C3489;margin-bottom:2px">🤖 Confused about a finding?</div><div style="font-size:12px;color:#3C3489">Ask AI to explain any issue in plain English and suggest how to fix it.</div></div><a href="{_ask_url}" target="_blank" style="font-size:12px;padding:7px 16px;border-radius:20px;background:#534AB7;color:#fff;text-decoration:none;white-space:nowrap;font-weight:500">Ask AI about this report →</a></div>')

    # Layers
    if layers:
        out.append('<div class="st">Layer Analysis</div>')
        for layer in layers:
            status = layer.get("status","passing")
            ex = layer.get("expert",{})
            lrn = layer.get("learner",{})
            sc = {"critical":"#E24B4A","warning":"#EF9F27","passing":"#1D9E75"}.get(status,"#999")
            findings_html = ""
            for f2 in ex.get("findings",[]):
                sev = f2.get("severity","passing")
                findings_html += f'<div class="finding" style="background:{sev_bg.get(sev,"#EAF3DE")};color:{sev_tc.get(sev,"#27500A")}"><strong>{f2.get("title","")}</strong> — {f2.get("detail","")}</div>'
            analogy = f'<div style="background:#EEEDFE;border-radius:8px;padding:.6rem .8rem;font-size:13px;color:#3C3489;margin-bottom:.5rem;font-style:italic">&#128161; {lrn["analogy"]}</div>' if lrn.get("analogy") else ""
            concept = f'<div style="background:#534AB7;color:#fff;border-radius:8px;padding:.6rem .8rem;font-size:13px;margin-top:.5rem">&#128161; Key concept: {lrn["key_concept"]}</div>' if lrn.get("key_concept") else ""
            out.append(f'<div class="layer"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.65rem"><span style="font-weight:600;font-size:14px">{layer.get("name","")}</span><span style="color:{sc};font-size:12px;font-weight:600;text-transform:uppercase">{status}</span></div>{analogy}<div style="font-size:13px;color:#555;margin-bottom:.5rem">{ex.get("summary","")}</div>{findings_html}{concept}</div>')

    # Fixes
    if fixes:
        out.append('<div class="st">Recommended Fixes</div>')
        for fix in fixes:
            prompt = f'<div style="font-size:12px;color:#888;margin-top:.35rem">Fix prompt:</div><div class="pb">{fix.get("lovable_prompt","")}</div>' if fix.get("lovable_prompt") else ""
            out.append(f'<div class="fix"><div style="font-weight:600;margin-bottom:.35rem">{fix.get("priority","")}. {fix.get("title","")}</div><div style="font-size:13px;color:#555;margin-bottom:.35rem">{fix.get("why_it_matters","")}</div><div style="font-size:13px;color:#444"><strong>How:</strong> {fix.get("how_to_fix","")}</div><div style="font-size:12px;color:#888">Effort: {fix.get("estimated_effort","")}</div>{prompt}</div>')

    # Second opinion
    if so.get("summary_prompt"):
        out.append(f'<div class="st">Second Opinion Prompts</div><div class="card"><div style="font-size:13px;font-weight:500;margin-bottom:.35rem">General review</div><div class="pb">{so["summary_prompt"]}</div></div>')

    out.append('<div style="background:#f8f8fc;border-radius:10px;padding:.85rem 1rem;margin:1rem 0;font-size:12px;color:#888;line-height:1.6;text-align:center">Scores may vary slightly between runs as findings are AI-generated. A meaningful improvement (e.g. C &rarr; B) after applying fixes indicates real progress.<br><br><strong style=\'color:var(--txt)\'>AI disclaimer:</strong> Analysis is generated by Claude AI and may contain false positives or miss issues. Always verify findings with your AI builder before making changes. This is not a professional security audit. <a href=\'/terms\' style=\'color:#534AB7\'>See full terms</a>.</div>')
    out.append(f'<div class="footer">Generated by <a href="https://verilay.dev" style="color:#534AB7">Verilay</a> on {data.get("generated_at","")} &nbsp;·&nbsp; <a href="https://verilay.dev" style="color:#534AB7">Analyse your own app &rarr;</a> &nbsp;·&nbsp; <a href="https://github.com/ekbm/verilay" style="color:#534AB7">&#11088; Star on GitHub</a></div></div></body></html>')

    return "".join(out)


@app.route("/export/markdown/<report_id>")
def export_markdown(report_id):
    entry_data = get_report_data(report_id)
    if not entry_data: return "Report not found", 404
    md = build_markdown(entry_data)
    return Response(md, mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=verilay-{report_id}.md"})


@app.route("/badge/<path:repo>")
def badge(repo):
    score = "?"
    if _HAS_SUPABASE:
        try:
            result = _sb.table("reports").select("score").eq("repo", repo).order("created_at", desc=True).limit(1).execute()
            if result.data:
                score = result.data[0].get("score", "?") or "?"
        except:
            pass
    else:
        latest = None
        for entry in _reports.values():
            if entry["data"].get("repo","") == repo:
                if latest is None or entry["saved_at"] > latest["saved_at"]:
                    latest = entry
        score = latest["data"].get("health",{}).get("score","?") if latest else "?"
    color = {"A":"#1D9E75","B":"#4A90D9","C":"#EF9F27","D":"#E24B4A","F":"#A32D2D"}.get(score,"#999")
    lw, vw = 58, 28
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw+vw}" height="20">'
           f'<rect width="{lw}" height="20" fill="#555"/>'
           f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
           f'<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="11">'
           f'<text x="{lw//2}" y="14">Verilay</text>'
           f'<text x="{lw+vw//2}" y="14">{score}</text>'
           f'</g></svg>')
    return Response(svg, mimetype="image/svg+xml",
        headers={"Cache-Control":"no-cache,no-store"})


def build_markdown(data):
    repo = data.get("repo","unknown")
    h = data.get("health",{})
    pr = data.get("prod_ready",{})
    md_label, _mdc, md_reason = verdict_from_score(h.get("score","C"))
    lines = [f"# Verilay Report: {repo}",
             f"Generated: {data.get('generated_at','')}","",
             "## Production Verdict",
             f"**{md_label}**",
             md_reason,"",
             f"## Health: {h.get('score','?')} — Critical: {h.get('critical',0)}, Warnings: {h.get('warnings',0)}, Passing: {h.get('passing',0)}","",
             "## Stack"]
    for s in data.get("stack",[]): lines.append(f"- **{s.get('name','')} {s.get('version','')}** ({s.get('category','')}) — {s.get('plain_english','')}")
    lines += ["","## Layers"]
    for layer in data.get("layers",[]):
        lines += [f"### {layer.get('name','')} — {layer.get('status','').upper()}"]
        ex = layer.get("expert",{})
        if ex.get("summary"): lines.append(f"**Expert:** {ex.get('summary','')}")
        for f2 in ex.get("findings",[]):
            lines.append(f"- **{f2.get('severity','').upper()}: {f2.get('title','')}** — {f2.get('detail','')}")
        lines.append("")
    for fix in data.get("top_fixes",[]):
        lines += [f"### Fix {fix.get('priority','')}: {fix.get('title','')}", f"**Why:** {fix.get('why_it_matters','')}", f"**How:** {fix.get('how_to_fix','')}", f"**Effort:** {fix.get('estimated_effort','')}",""]
    so = data.get("second_opinion",{})
    if so.get("summary_prompt"):
        lines += ["## Second Opinion","```",so.get("summary_prompt",""),"```"]
    lines += ["---","*Generated by [Verilay](https://verilay.dev)*"]
    return "\n".join(lines)


def _js_version():
    """Short hash of app.js, used to cache-bust the <script> tag.

    'Cache-Control: no-cache' alone was not enough — Cloudflare caches .js by
    file extension, so a deploy could leave users on the previous script while
    the new HTML expected the new one. A changing query string sidesteps every
    cache in the chain. Computed once per worker at import time.
    """
    import hashlib
    import os
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.js")
        with open(p, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:10]
    except Exception:
        return "dev"


JS_VERSION = _js_version()


@app.route("/")
def index():
    count = get_analysis_count()
    nav_desktop, nav_mobile = _account_nav()
    try:
        self_monitor.maybe_tick()
        selfmon_badge = self_monitor.badge_html()
        selfmon_table = self_monitor.sample_table_html() if selfmon_badge else ""
    except Exception as e:
        print(f"[self-monitor] widget failed (non-critical): {e}", flush=True)
        selfmon_badge = selfmon_table = ""
    html = (HTML.replace("__JSVER__", JS_VERSION)
                .replace("__ACCOUNTNAV__", nav_desktop)
                .replace("__ACCOUNTNAV_MOBILE__", nav_mobile)
                .replace("__SELFMONITOR_BADGE__", selfmon_badge)
                .replace("__SELFMONITOR_TABLE__", selfmon_table))
    return render_template_string(html, analysis_count=count if count > 0 else "")


@app.route("/static/app.js")
def serve_js():
    import os
    js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.js')
    try:
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
        return Response(js_content, mimetype='application/javascript',
            headers={'Cache-Control': 'public, max-age=31536000, immutable'})
    except Exception as e:
        return f"// app.js not found: {e}", 404


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verilay - Understand your AI-built app</title>
<!-- Privacy-friendly analytics by Plausible -->
<script defer data-domain="verilay.dev" src="https://plausible.io/js/script.outbound-links.file-downloads.tagged-events.js"></script>
<script>window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)}</script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/dist/tabler-icons.min.css">
<style>
:root{
  --bg:#f8f8f7;--sur:#fff;--bdr:#e8e6e0;--txt:#1a1917;--mut:#6b6966;--r:10px;
  --pu:#534AB7;--pul:#EEEDFE;--put:#3C3489;
  --gr:#1D9E75;--grl:#E1F5EE;--grt:#085041;
  --or:#EF9F27;--orl:#FAEEDA;--ort:#633806;
  --rd:#E24B4A;--rdl:#FCEBEB;--rdt:#A32D2D;
  --bll:#E6F1FB;--blt:#0C447C;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;font-size:16px}
.wrap{max-width:1100px;margin:0 auto;padding:2rem 2.5rem}
#nav-toggle:checked + #burger-menu{display:block!important}
#nav-toggle:checked + * #burger-btn{background:var(--pul);color:var(--pu)}
@media(max-width:768px){.wrap{padding:1rem 1rem!important}#nav-links{display:none!important}#burger-btn{display:flex!important;align-items:center}.layer-panel{flex-direction:column!important}#layer-nav{width:100%!important;min-width:0!important;border-right:none!important;border-bottom:0.5px solid var(--bdr)!important;display:flex!important;flex-direction:row!important;flex-wrap:wrap!important;gap:4px!important;padding:.5rem!important;overflow-x:auto}#layer-nav .lb{flex:1 1 calc(33% - 4px)!important;min-width:80px!important;font-size:12px!important;padding:6px 8px!important}#layer-content{padding:.75rem!important}.hcs{grid-template-columns:1fr 1fr!important}.hc{min-width:0!important}h1{font-size:1.6rem!important}#hero-section{padding:0!important}}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:.3rem}
.logo-text{font-size:24px;font-weight:600;color:var(--pu)}
.tagline{font-size:15px;color:var(--mut);margin-bottom:2rem}
.label{font-size:15px;font-weight:500;margin-bottom:.65rem}
.mg{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:1.25rem}
.mc{border:1.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem;cursor:pointer;background:var(--sur);transition:all .15s;user-select:none}
.mc:hover{border-color:#aaa8ff}
.mc.sel{border-color:var(--pu);background:var(--pul)}
.mc-icon{font-size:20px;margin-bottom:.4rem}
.mc-title{font-size:14px;font-weight:500;margin-bottom:2px}
.mc-desc{font-size:12px;color:var(--mut);line-height:1.4}
.mbadge{font-size:12px;font-weight:500;padding:2px 7px;border-radius:20px;margin-top:5px;display:inline-block}
.ip{display:none;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:1rem}
.ip.vis{display:block}
.lbl{font-size:13px;font-weight:500;margin-bottom:.4rem;display:block}
.sub{font-size:12px;color:var(--mut);margin-bottom:.6rem;line-height:1.45}
input[type=url],input[type=text]{width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:9px 12px;font-size:14px;background:var(--bg);color:var(--txt);outline:none}
input:focus{border-color:var(--pu)}
.hint{background:var(--pul);border-radius:8px;padding:.65rem .85rem;font-size:13px;color:var(--put);margin-top:.65rem;line-height:1.5}
.hint ol{margin-top:.35rem;padding-left:1.1rem}
.hint li{margin-bottom:2px}
.fd{border:1.5px dashed var(--bdr);border-radius:8px;padding:1.5rem;text-align:center;cursor:pointer;position:relative;transition:all .15s;background:var(--bg)}
.fd:hover{border-color:var(--pu);background:var(--pul)}
.fd input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.erbox{background:var(--rdl);border-radius:var(--r);padding:1rem;color:var(--rdt);font-size:14px;margin-bottom:1rem;display:none}
.erbox.vis{display:block}
.btn{width:100%;padding:12px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:15px;font-weight:500;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px}
.btn:hover{opacity:.9}
.btn:disabled{opacity:.5;cursor:not-allowed}
.ld{display:none;text-align:center;padding:2.5rem}
.ld.vis{display:block}
.spin{width:36px;height:36px;border:3px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;margin:0 auto 1rem}
@keyframes sp{to{transform:rotate(360deg)}}
.rpt{display:none}
.rpt.vis{display:block}
.sticky-bar{display:flex;align-items:center;justify-content:space-between;padding:.65rem .9rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);position:sticky;top:0;z-index:10;margin-bottom:1rem}
.btn-sm{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:20px;background:var(--pu);color:#fff;font-size:13px;font-weight:500;border:none;cursor:pointer}
.prod-banner{border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.rh{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.1rem;margin-bottom:10px}
.pill{font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;display:inline-block;margin:2px}
.hg{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:.65rem}
.hc{border-radius:8px;padding:.55rem;text-align:center}
.tabs{display:flex;gap:5px;margin-bottom:1rem;flex-wrap:wrap}
.tab{padding:5px 14px;border-radius:20px;font-size:13px;font-weight:500;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut)}
.tab.on{background:var(--pu);color:#fff;border-color:transparent}
.panel{display:none}.panel.on{display:block}
.ll{display:grid;grid-template-columns:175px 1fr;gap:12px}
.lnav{display:flex;flex-direction:column;gap:5px}
.lb{display:flex;align-items:center;gap:8px;padding:7px 9px;border-radius:8px;cursor:pointer;border:0.5px solid transparent;background:var(--bg);width:100%;text-align:left;font-size:13px;font-weight:500}
.lb:hover,.lb.act{background:var(--sur);border-color:var(--bdr)}
.ldot{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-left:auto}
.lico{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.ca{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem;min-height:280px}
.mt{display:flex;gap:4px;margin-bottom:.85rem;flex-wrap:wrap}
.mb{font-size:12px;font-weight:500;padding:4px 14px;border-radius:20px;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);transition:all .15s}
.mb.on{background:var(--pu);color:#fff;border-color:transparent}
.mb[data-mode="learner"]{border-color:var(--pu);color:var(--put)}
.mb[data-mode="learner"].on{background:var(--pu);color:#fff}
.mb[data-mode="learner"]::before{content:"✦ ";font-size:12px}
.finding{border-radius:8px;padding:.75rem .95rem;margin-bottom:8px;display:flex;align-items:flex-start;gap:8px;font-size:13px;line-height:1.5}
.lc{background:var(--bg);border-left:2px solid var(--pu);border-radius:0 8px 8px 0;padding:.65rem .85rem;margin-bottom:7px}
.lc-title{font-size:13px;font-weight:500;margin-bottom:3px}
.lc-body{font-size:13px;color:var(--mut);line-height:1.5}
.analogy{background:var(--pul);border-left:3px solid var(--pu);border-radius:0 8px 8px 0;padding:.75rem .95rem;margin-bottom:10px;font-size:15px;color:var(--put);line-height:1.6;font-style:italic}
.learner-section{background:linear-gradient(135deg,var(--pul) 0%,transparent 100%);border:0.5px solid var(--pu);border-radius:var(--r);padding:1rem;margin-bottom:8px}
.learner-label{font-size:12px;font-weight:600;color:var(--pu);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem;display:flex;align-items:center;gap:5px}
.key-concept{background:var(--pu);color:#fff;border-radius:8px;padding:.65rem .9rem;margin:.5rem 0;font-size:13px;line-height:1.55}
.qcard{background:var(--pul);border-radius:8px;padding:.75rem .9rem;margin-bottom:7px}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px}
.sc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.7rem .85rem}
.fc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.si{border-radius:8px;padding:.6rem .85rem;margin-bottom:6px;display:flex;align-items:center;gap:8px;font-size:13px;font-weight:500}
.so-card{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.p2-banner{background:var(--pul);border:1.5px solid var(--pu);border-radius:var(--r);padding:1.1rem 1.25rem;margin-top:1.25rem;display:none}
.bottom-cta{margin-top:1.5rem;padding:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);text-align:center}
@media(max-width:540px){.mg{grid-template-columns:1fr}.ll{grid-template-columns:1fr}.hg{grid-template-columns:repeat(2,1fr)}}
@media(max-width:640px){body{font-size:16px}.wrap{padding:1.25rem 1rem}}
/* Accessibility: underline links inside text blocks */
.hint a,.scope-notice a,.next-steps a,p a{text-decoration:underline;text-underline-offset:2px}
#hero-section a,#report-content a{text-decoration:underline;text-underline-offset:2px}
@media(min-width:900px){
  .ll{grid-template-columns:200px 1fr;gap:16px}
  .mg{grid-template-columns:repeat(3,1fr)}
  .hg{grid-template-columns:repeat(4,1fr)}
}
@media(min-width:1200px){
  .ll{grid-template-columns:220px 1fr;gap:20px}
}
@media print{
  .sticky-bar,.p2-banner,.bottom-cta,#hero-section,#form-section,.ld,#btn-new,#btn-new2,#btn-save-report,#btn-export-md,#btn-print,#btn-back-hero,#share-banner{display:none!important}
  .rpt{display:block!important}
  body{background:white;padding:0}
  .wrap{max-width:100%;padding:1rem}
  .ca{min-height:auto}
}
</style>
<script src="/static/app.js?v=__JSVER__"></script>
</head>
<body>
<main><div class="wrap">

<!-- ── Nav ─────────────────────────────────────────────────── -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2.5rem;min-width:0;overflow:hidden">
  <div style="display:flex;align-items:center;gap:8px">
    <svg width="28" height="28" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><rect width="44" height="44" rx="10" fill="#534AB7"/><path d="M15.4 15.6 L22 29.5 L28.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M13.4 15.6 L30.6 15.6" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round"/></svg>
    <span style="font-size:18px;font-weight:700;color:var(--pu)">Verilay</span>
    <span style="font-size:12px;color:var(--mut);background:var(--bg);border:0.5px solid var(--bdr);padding:2px 7px;border-radius:20px;margin-left:2px">verification layer</span>
  </div>
  <div style="display:flex;align-items:center;gap:8px">
    <!-- Desktop nav links — hidden on mobile -->
    <div id="nav-links" style="display:flex;gap:6px;align-items:center">
      __ACCOUNTNAV__
      <a href="/ask-verilay" style="display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:5px 11px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);text-decoration:none">Ask Verilay</a>
      <a href="/about" style="display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:5px 11px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);text-decoration:none">About</a>
      <a href="/blog" style="display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:5px 11px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);text-decoration:none">Blog</a>
      <a href="https://github.com/ekbm/verilay" target="_blank" style="display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:5px 11px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);text-decoration:none">GitHub</a>
    </div>
    <button id="btn-start-hero" style="display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:5px 14px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer;font-weight:500;white-space:nowrap">
      Analyse my app
    </button>
    <!-- CSS-only burger using label+checkbox — no JS needed, works on all mobile -->
    <label for="nav-toggle" id="burger-btn" style="display:none;padding:10px 12px;cursor:pointer;border:0.5px solid var(--bdr);border-radius:8px;color:var(--txt);user-select:none;-webkit-tap-highlight-color:transparent">
      &#9776;
    </label>
  </div>
</div>
<input type="checkbox" id="nav-toggle" style="display:none">
<!-- Mobile dropdown menu — CSS controlled -->
<div id="burger-menu" style="background:var(--sur);border-bottom:0.5px solid var(--bdr);padding:.75rem 1.5rem;display:none">
  <div style="display:flex;flex-direction:column;gap:.5rem">
    __ACCOUNTNAV_MOBILE__
    <a href="/ask-verilay" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">Ask Verilay</a>
    <a href="/about" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">About</a>
    <a href="/blog" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">Blog</a>
    <a href="/changelog" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">Changelog</a>
    <a href="/privacy" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">Privacy</a>
    <a href="/terms" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">Terms</a>
    <a href="/ai-disclaimer" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0;border-bottom:0.5px solid var(--bdr)">AI Disclaimer</a>
    <a href="https://github.com/ekbm/verilay" target="_blank" style="font-size:16px;color:var(--txt);text-decoration:none;padding:.6rem 0">GitHub</a>
  </div>
</div>

<!-- ── Hero ────────────────────────────────────────────────── -->
<div id="hero-section">
  <div style="text-align:center;padding:2rem 0 1.5rem">
    <div style="display:inline-flex;align-items:center;gap:6px;background:var(--pul);color:var(--put);font-size:12px;font-weight:500;padding:4px 12px;border-radius:20px;margin-bottom:1.25rem">
      <i class="ti ti-sparkles" style="font-size:13px"></i>
      Free &amp; open source — built for non-developers
    </div>
    <h1 style="font-size:clamp(1.75rem,4vw,3rem);font-weight:700;line-height:1.2;margin-bottom:.85rem;letter-spacing:-.02em">
      Find out if your <span style="color:var(--pu)">AI-built app</span><br>
      is safe to launch
    </h1>
    <p style="font-size:16px;color:var(--mut);max-width:580px;margin:0 auto 2rem;line-height:1.65">
      You built something with Lovable, Replit, or Bolt. But do you know if it's secure? What libraries it uses? Whether it's ready to ship? Verilay tells you — in plain English.
    </p>
    <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:.9rem">
      {% if analysis_count %}
      <span style="font-size:13px;color:var(--mut);background:var(--sur);border:0.5px solid var(--bdr);padding:5px 16px;border-radius:20px;display:inline-block">
        🔍 {{ analysis_count }} apps analysed so far
      </span>
      {% endif %}
      __SELFMONITOR_BADGE__
    </div>
    <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:.9rem">
      <button id="btn-hero-analyse" style="display:inline-flex;align-items:center;gap:7px;padding:12px 24px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:15px;font-weight:500;border:none;cursor:pointer">
        <i class="ti ti-search" style="font-size:16px"></i> Analyse my app — it's free
      </button>
      <button id="btn-hero-demo" style="display:inline-flex;align-items:center;gap:7px;padding:12px 24px;border-radius:var(--r);background:transparent;color:var(--txt);font-size:15px;font-weight:500;border:1.5px solid var(--bdr);cursor:pointer">
        <i class="ti ti-player-play" style="font-size:16px"></i> See a sample report
      </button>
    </div>
    <p style="font-size:14px;color:var(--mut);max-width:520px;margin:0 auto 2.5rem;line-height:1.6">
      No account, nothing to install. Verilay reads your files only to build the report — and it's
      <a href="https://github.com/ekbm/verilay" target="_blank" rel="noopener" style="color:var(--pu);text-decoration:underline">open source</a>,
      so you can see exactly what it does.
    </p>
  </div>

  <!-- Problem → Solution strip -->
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--bdr);border-radius:var(--r);overflow:hidden;margin-bottom:2.5rem">
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">🤖</div>
      <div style="font-size:14px;font-weight:500;margin-bottom:4px">AI built your app</div>
      <div style="font-size:13px;color:var(--mut);line-height:1.5">Lovable, Replit, Bolt, v0, Cursor — powerful tools that generate real code fast.</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">❓</div>
      <div style="font-size:14px;font-weight:500;margin-bottom:4px">But can you trust it?</div>
      <div style="font-size:13px;color:var(--mut);line-height:1.5">Is your login secure? Are your database credentials exposed? Is it ready for real users?</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">🔍</div>
      <div style="font-size:14px;font-weight:500;margin-bottom:4px">Verilay answers that</div>
      <div style="font-size:13px;color:var(--mut);line-height:1.5">Reads every layer of your app. Explains it in plain English. Flags issues. Gives you a second opinion.</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">✅</div>
      <div style="font-size:14px;font-weight:500;margin-bottom:4px">Ship with confidence</div>
      <div style="font-size:13px;color:var(--mut);line-height:1.5">Know exactly what you built and whether it's ready. No developer needed to understand the results.</div>
    </div>
  </div>

  <!-- How it works -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;font-size:14px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:1.1rem">How it works</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px">

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;position:relative">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">1</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:.3rem">Analyse</div>
        <div style="font-size:13px;color:var(--mut);line-height:1.55">Paste your GitHub link, upload a ZIP, or enter your live app URL. Verilay reads every layer of your app in 30 seconds.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">2</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:.3rem">Check issues</div>
        <div style="font-size:13px;color:var(--mut);line-height:1.55">See what was found across 6 layers — Auth, Database, API, Frontend, Config, Libraries. Each issue rated critical, warning, or passing.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">3</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:.3rem">Learn</div>
        <div style="font-size:13px;color:var(--mut);line-height:1.55">Switch to Learner mode for plain-English explanations, real-world analogies, and optional quizzes — so you actually understand what was built.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">4</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:.3rem">Fix and re-run</div>
        <div style="font-size:13px;color:var(--mut);line-height:1.55">Copy the ready-to-paste fix prompt, apply it in Lovable or Replit, then re-run Verilay to confirm the issue is resolved and your score improves.</div>
      </div>

    </div>
  </div>

  <!-- What you get -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;font-size:14px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:1.1rem">What Verilay gives you</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px">
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-stack-2" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Tech stack map</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Every library and framework detected and explained in plain English.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-layers-difference" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Layer map</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Auth, Database, API, Frontend — each layer explained with expert and learner views.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-shield-check" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Security check</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Exposed secrets, auth issues, outdated libraries — flagged before they become problems.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-rocket" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Production verdict</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Green, amber, or red — is your app ready to ship to real users?</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-school" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Learner mode</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Understand what each part of your app does with real-world analogies and quizzes.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-message-check" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:13px;font-weight:500">Second opinion</span>
        </div>
        <div style="font-size:12px;color:var(--mut);line-height:1.45">Copy-ready prompts to verify findings in Claude, ChatGPT, or with a developer.</div>
      </div>
    </div>
    <div style="text-align:center;margin-top:1rem">__SELFMONITOR_TABLE__</div>
  </div>

  <!-- Honest scope statement -->
  <div style="background:var(--bg);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.25rem;margin-bottom:2rem;display:flex;align-items:flex-start;gap:10px">
    <i class="ti ti-info-circle" style="font-size:16px;color:var(--mut);flex-shrink:0;margin-top:1px"></i>
    <div style="font-size:13px;color:var(--mut);line-height:1.6">
      <strong style="color:var(--txt)">What Verilay covers — and what it doesn't.</strong>
      Verilay gives you a plain-English first-pass overview of your AI-built app. It explains your tech stack, flags obvious issues, and helps you understand what was built — whether you wrote the code yourself or not.
      <br><br>
      <strong style="color:var(--txt)">For developers:</strong> Think of it as a quick orientation layer — useful before diving into a deeper review with your own tools.
      It won't replace your expertise, but it gives you and your non-technical collaborators a shared starting point.
      <br><br>
      <strong style="color:var(--txt)">For non-developers:</strong> This is built for you.
      No coding knowledge needed to understand the findings or act on them.
      <br><br>
      Scores may vary slightly between runs as findings are AI-generated. A meaningful improvement
      (e.g. C &rarr; B) after applying fixes indicates real progress. Minor variations of one grade
      are normal and don't necessarily reflect a change in your app's security.
      <br><br>
      Treat findings as <strong>things to verify, not things to fix</strong> — confirm each issue exists in your app before making changes.
      It is <em>not</em> a penetration test or a professional security audit.
      For apps going live with real user data or payments, get a deeper review before launch — every report
      ends with second opinion prompts and names the specific tools worth using, so you'll know exactly what
      to do next.
    </div>
  </div>

  <!-- Learner mode highlight -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;margin-bottom:1.25rem">
      <div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.4rem">What makes Verilay different</div>
      <div style="font-size:20px;font-weight:700;letter-spacing:-.01em;margin-bottom:.4rem">Built for people who <span style="color:var(--pu)">didn't write the code</span></div>
      <div style="font-size:14px;color:var(--mut);max-width:480px;margin:0 auto">Every finding comes in two modes. Switch between them any time.</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <!-- Developer mode -->
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.1rem;opacity:.7">
        <div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:6px">
          <i class="ti ti-code" style="font-size:14px"></i> Expert mode
        </div>
        <div style="background:var(--rdl);border-radius:8px;padding:.65rem .85rem;font-size:13px;color:var(--rdt);line-height:1.5">
          <div style="font-weight:500;margin-bottom:3px">JWT tokens have no expiry configured</div>
          <div style="font-size:12px;opacity:.85">Supabase auth.session.expires_in not set. Tokens are valid indefinitely, creating persistent session hijacking risk. CWE-613.</div>
        </div>
      </div>
      <!-- Learner mode -->
      <div style="background:var(--sur);border:1.5px solid var(--pu);border-radius:var(--r);padding:1.1rem;position:relative">
        <div style="position:absolute;top:-10px;left:50%;transform:translateX(-50%);background:var(--pu);color:#fff;font-size:12px;font-weight:600;padding:2px 10px;border-radius:20px;white-space:nowrap">Your view</div>
        <div style="font-size:12px;font-weight:600;color:var(--put);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:6px">
          <i class="ti ti-school" style="font-size:14px"></i> Learner mode
        </div>
        <div style="background:var(--pul);border-radius:8px;padding:.55rem .75rem;font-size:13px;color:var(--put);margin-bottom:.5rem;line-height:1.5">
          <i class="ti ti-bulb" style="font-size:13px;margin-right:4px"></i>
          <strong>Think of it like this:</strong> Login tokens are like hotel key cards. Right now yours never expire - a stolen key card works forever.
        </div>
        <div style="background:var(--rdl);border-radius:8px;padding:.55rem .75rem;font-size:13px;color:var(--rdt);line-height:1.5;margin-bottom:.5rem">
          <div style="font-weight:500;margin-bottom:2px">Login sessions never expire</div>
          <div style="font-size:12px">If someone steals a login token, they have permanent access to that account - even after the user changes their password.</div>
        </div>
        <div style="background:var(--grl);border-radius:8px;padding:.55rem .75rem;font-size:12px;color:var(--grt);line-height:1.5">
          <strong>Verify & Fix in Lovable:</strong> "Add a 24-hour session expiry to my Supabase auth configuration"
        </div>
      </div>
    </div>
    <!-- Quiz teaser -->
    <div style="margin-top:10px;background:var(--pul);border-radius:var(--r);padding:.85rem 1rem;display:flex;align-items:center;gap:12px">
      <i class="ti ti-brain" style="font-size:22px;color:var(--pu);flex-shrink:0"></i>
      <div>
        <div style="font-size:14px;font-weight:500;color:var(--put);margin-bottom:2px">Test your understanding with optional quizzes</div>
        <div style="font-size:13px;color:var(--put);opacity:.85">Every layer includes a quiz question so you actually learn what was built - not just what was wrong.</div>
      </div>
    </div>
  </div>

  <!-- Ask Verilay prompt -->
  <div style="max-width:600px;margin:0 auto 2.5rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.5rem 1.5rem 1.35rem;text-align:center">
    <div style="font-size:16px;font-weight:600;margin-bottom:.3rem">💬 Or just ask us anything</div>
    <div style="font-size:14px;color:var(--mut);margin-bottom:1.1rem;line-height:1.6">New to building with AI? Ask Verilay answers your questions in plain English — free, no jargon.</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:center">
      <a href="/ask-verilay?q=How%20do%20I%20back%20up%20my%20code%20to%20GitHub%3F" style="font-size:13.5px;color:var(--txt);background:var(--bg);border:0.5px solid var(--bdr);border-radius:20px;padding:7px 14px;text-decoration:none">How do I back up my code to GitHub?</a>
      <a href="/ask-verilay?q=How%20do%20I%20add%20payments%20to%20my%20app%3F" style="font-size:13.5px;color:var(--txt);background:var(--bg);border:0.5px solid var(--bdr);border-radius:20px;padding:7px 14px;text-decoration:none">How do I add payments?</a>
      <a href="/ask-verilay?q=Is%20my%20app%20safe%20to%20launch%3F" style="font-size:13.5px;color:var(--txt);background:var(--bg);border:0.5px solid var(--bdr);border-radius:20px;padding:7px 14px;text-decoration:none">Is my app safe to launch?</a>
      <a href="/ask-verilay?q=Why%20is%20my%20app%20slow%3F" style="font-size:13.5px;color:var(--txt);background:var(--bg);border:0.5px solid var(--bdr);border-radius:20px;padding:7px 14px;text-decoration:none">Why is my app slow?</a>
    </div>
    <a href="/ask-verilay" style="display:inline-block;margin-top:1.1rem;font-size:14px;color:var(--pu);text-decoration:none;font-weight:500">Open Ask Verilay &rarr;</a>
  </div>

  <!-- Platforms -->
  <div style="text-align:center;margin-bottom:2.5rem">
    <div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">Works with apps built on</div>
    <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px">
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🔷 Lovable</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🟢 Replit</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">⚡ Bolt</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🔲 v0</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🌀 Cursor</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🌊 Windsurf</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🚀 Emergent</span>
      <span style="font-size:13px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">+ any GitHub repo</span>
    </div>
  </div>

  <!-- CTA -->
  <div style="text-align:center;background:var(--pul);border-radius:var(--r);padding:1.75rem 1.5rem;margin-bottom:2rem">
    <div style="font-size:17px;font-weight:600;margin-bottom:.4rem">Ready to see what's inside your app?</div>
    <div style="font-size:14px;color:var(--mut);margin-bottom:1.1rem">Free. Takes 30 seconds. No account needed.</div>
    <button id="btn-hero-cta" style="display:inline-flex;align-items:center;gap:7px;padding:12px 28px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:15px;font-weight:500;border:none;cursor:pointer">
      <i class="ti ti-search" style="font-size:16px"></i> Analyse my app
    </button>
  </div>
</div>

<!-- ── Analysis history ─────────────────────────────────── -->
<div id="history-section" style="display:none;margin-bottom:1.5rem">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.65rem">
    <div style="font-size:13px;font-weight:500;color:var(--mut);display:flex;align-items:center;gap:6px">
      <i class="ti ti-history" style="font-size:15px"></i> Recent analyses
    </div>
    <button id="btn-clear-history" style="font-size:12px;padding:3px 10px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">Clear</button>
  </div>
  <div id="history-list" style="display:flex;flex-direction:column;gap:6px"></div>
  <div id="history-show-more" style="display:none;text-align:center;margin-top:6px">
    <button onclick="toggleOlderHistory()" id="btn-show-more" style="font-size:12px;padding:4px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">Show older analyses ▾</button>
  </div>
</div>

<!-- ── Analysis form (hidden until user clicks analyse) ──── -->
<div id="form-section" style="display:none">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:1.25rem">
    <button id="btn-back-hero" style="display:inline-flex;align-items:center;gap:5px;font-size:13px;padding:5px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">
      <i class="ti ti-arrow-left" style="font-size:14px"></i> Back
    </button>
    <span style="font-size:15px;font-weight:500">Analyse your app</span>
  </div>
  <p class="label">How do you want to share your project?</p>
  <div class="mg">
    <div class="mc sel" id="mc-github">
      <div class="mc-icon"><i class="ti ti-brand-github"></i></div>
      <div class="mc-title">GitHub URL</div>
      <div class="mc-desc">Paste your repo link. Works for Lovable, Replit, any GitHub project.</div>
      <span class="mbadge" style="background:var(--grl);color:var(--grt)">Most complete</span>
    </div>
    <div class="mc" id="mc-zip">
      <div class="mc-icon"><i class="ti ti-file-zip"></i></div>
      <div class="mc-title">Upload ZIP</div>
      <div class="mc-desc">Export from Lovable or Replit and upload here. No GitHub account needed.</div>
      <span class="mbadge" style="background:var(--pul);color:var(--put)">No GitHub needed</span>
    </div>
    <div class="mc" id="mc-url">
      <div class="mc-icon"><i class="ti ti-world"></i></div>
      <div class="mc-title">Live URL</div>
      <div class="mc-desc">Paste your published app link. Surface scan only.</div>
      <span class="mbadge" style="background:var(--orl);color:var(--ort)">Quick scan</span>
    </div>
  </div>

  <div class="ip vis" id="p-github">
    <label class="lbl">Repository URL</label>
    <p class="sub">Works with GitHub, GitLab, Bitbucket, and Azure DevOps</p>
    <input type="url" id="gh-url" placeholder="https://github.com/username/project">
    <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.75rem 1rem;margin-top:.65rem">
      <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="toggleAccuracyTip()">
        <div style="font-size:13px;font-weight:600;color:var(--mut)">Optional — how to get fewer false positives</div>
        <i class="ti ti-chevron-down" id="accuracy-tip-ico" style="font-size:13px;color:var(--mut)"></i>
      </div>
      <div id="accuracy-tip" style="display:none;margin-top:.65rem">
        <div style="font-size:13px;color:var(--mut);line-height:1.6;margin-bottom:.65rem">
          Go ahead and scan now — this changes nothing about whether your keys and passwords get checked.
          It only helps the deeper review: ask your AI builder (Lovable, Replit, Cursor etc) to add auth
          posture comments to your edge functions, so Verilay can tell which ones are intentionally public
          instead of having to guess.
        </div>
        <div style="font-size:12px;font-weight:600;color:var(--mut);margin-bottom:.35rem">Copy this prompt and paste it into your AI builder:</div>
        <div style="background:#fff;border:0.5px solid #F59E0B;border-radius:6px;padding:.6rem .75rem;font-size:12px;font-family:monospace;color:#444;line-height:1.6;position:relative">
          Add a JSDoc comment block to the top of each edge/serverless function with these fields: @auth-required: true|false, @auth-method: in-code|gateway|none, @public: true|false (and reason if true e.g. "inbound webhook" or "landing page demo"). Also create a SECURITY.md explaining your project auth model. This helps security scanners understand your app correctly.
          <button onclick="copyAccuracyPrompt()" style="position:absolute;top:6px;right:6px;font-size:12px;padding:3px 8px;border-radius:4px;background:#F59E0B;color:#fff;border:none;cursor:pointer" id="copy-accuracy-btn">Copy</button>
        </div>
      </div>
    </div>
    <div class="hint" style="background:var(--bg);border:0.5px solid var(--bdr)">
      <div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-bottom:.5rem">How to find your repo URL</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;font-size:12px;color:var(--mut)">
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔷 Lovable</div>
          Open project → click GitHub icon top-right → copy the URL shown
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🟢 Replit</div>
          Open your Repl → Version Control tab (left sidebar) → Connect to GitHub → copy URL
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">⚡ Bolt</div>
          Open project → click GitHub in the top toolbar → Push to GitHub → copy repo URL
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔲 v0 by Vercel</div>
          Open project → click the GitHub icon → Create repository → copy URL shown
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🌀 Cursor</div>
          Source Control panel (Ctrl+Shift+G) → Publish to GitHub → copy the repo URL
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🌊 Windsurf</div>
          Source Control panel → Publish to GitHub → copy the repo URL
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔵 GitLab</div>
          Paste your GitLab URL directly e.g. https://gitlab.com/user/project
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🟠 Bitbucket</div>
          Paste your Bitbucket URL e.g. https://bitbucket.org/user/project
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔷 Azure DevOps</div>
          Repos → select repo → Clone → HTTPS URL → paste above
        </div>
      </div>
      <div style="margin-top:.65rem;font-size:12px;color:var(--mut)">
        <strong style="color:var(--txt)">Note:</strong> Repo must be public for Verilay to read it, or connect with a personal access token in your .env file.
      </div>
    </div>
  </div>

  <div class="ip" id="p-zip">
    <label class="lbl">Upload your project ZIP</label>
    <p class="sub">Export your project as a ZIP from your AI builder — no GitHub account needed</p>
    <div style="background:#FEF3C7;border:0.5px solid #F59E0B;border-radius:8px;padding:.6rem .85rem;margin-bottom:.75rem;font-size:13px;color:#92400E;line-height:1.55">
      <strong>ZIP must be under 100MB.</strong> Downloads from Replit and some AI builders include large folders like <code>node_modules</code> that can make ZIPs several GB.
      <br><br>
      <strong>Replit users:</strong> Connect your project to GitHub (free at replit.com → Git tab) then use the GitHub URL method — faster, no size limit.
      <br>
      <strong>Lovable users:</strong> Use GitHub URL — Lovable auto-syncs every project to GitHub.
      <br>
      <strong>For ZIP uploads:</strong> Only zip your source files — exclude <code>node_modules</code>, <code>dist</code>, <code>build</code> folders.
    </div>
    <div class="fd" id="dz">
      <input type="file" id="zf" accept=".zip">
      <div style="font-size:24px;color:var(--mut);margin-bottom:.4rem"><i class="ti ti-upload"></i></div>
      <div style="font-size:14px;color:var(--mut)">Drop ZIP here or click to browse</div>
      <div id="fn" style="font-size:13px;color:var(--gr);margin-top:.4rem;font-weight:500"></div>
    </div>
    <div class="hint" style="background:var(--bg);border:0.5px solid var(--bdr);margin-top:.75rem">
      <div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-bottom:.5rem">How to export a ZIP from your builder</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;font-size:12px;color:var(--mut)">
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔷 Lovable</div>
          Open project → click the three-dot menu (···) top-right → Export project → Download ZIP
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🟢 Replit</div>
          Open your Repl → click the three-dot menu → Download as ZIP
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">⚡ Bolt</div>
          Open project → Files panel → Download Project (ZIP icon at top of file tree)
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🔲 v0 by Vercel</div>
          Open project → three-dot menu → Download → Download as ZIP
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🌀 Cursor / Windsurf</div>
          These are desktop apps — your files are already on your computer. Zip the project folder and upload here.
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🚀 Emergent</div>
          Open project → Settings → Export → Download ZIP
        </div>
        <div style="background:var(--sur);border-radius:6px;padding:.5rem .65rem">
          <div style="font-weight:600;color:var(--txt);margin-bottom:3px">🤖 Any AI assistant</div>
          If your AI generated files in a chat (Claude, ChatGPT etc) — save all files into a folder, select all, right-click → Send to → Compressed folder
        </div>
      </div>
    </div>
  </div>

  <div class="ip" id="p-url">
    <label class="lbl">Live app URL</label>
    <p class="sub">e.g. https://yourapp.lovable.app — surface scan only.</p>
    <input type="url" id="lu" placeholder="https://yourapp.lovable.app">
    <div class="hint" style="background:var(--orl);color:var(--ort)">
      Surface scan only — libraries and services detected but not security config or DB structure.
    </div>
  </div>

  <div class="erbox" id="eb"></div>
  <button class="btn" id="btn-analyse">
    <i class="ti ti-search"></i> Analyse my app
  </button>
</div>

<div class="ld" id="ld">
  <div style="max-width:420px;margin:0 auto">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:1.1rem">
      <div class="spin" style="flex-shrink:0"></div>
      <div>
        <div class="ld-msg" id="lm">Reading your project files...</div>
        <div style="font-size:12px;color:var(--mut);margin-top:2px" id="ls">Fetching from GitHub API</div>
      </div>
    </div>
    <div style="background:var(--bdr);border-radius:20px;height:6px;overflow:hidden;margin-bottom:.65rem">
      <div id="prog-bar" style="height:100%;border-radius:20px;background:linear-gradient(90deg,var(--pu),#8B7FE8);width:0%;transition:width 0.6s ease"></div>
    </div>
    <div style="display:flex;justify-content:space-between;margin-bottom:1.25rem">
      <span style="font-size:12px;color:var(--mut)" id="prog-pct">0%</span>
      <span style="font-size:12px;color:var(--mut)" id="prog-eta">~30 seconds</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px" id="step-list">
      <div class="step-item" id="step-0" data-step="0">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px">1</div>
          <span>Reading project files</span>
        </div>
      </div>
      <div class="step-item" id="step-1" data-step="1">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px">2</div>
          <span>Detecting tech stack</span>
        </div>
      </div>
      <div class="step-item" id="step-2" data-step="2">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px">3</div>
          <span>Analysing layers (Auth, DB, API...)</span>
        </div>
      </div>
      <div class="step-item" id="step-3" data-step="3">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px">4</div>
          <span>Running security checks</span>
        </div>
      </div>
      <div class="step-item" id="step-4" data-step="4">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px">5</div>
          <span>Writing plain-English explanations</span>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="rpt" id="rpt">
  <div id="surface-scan-notice" style="display:none;background:#FEF3C7;border:0.5px solid #F59E0B;border-radius:12px;padding:.75rem 1rem;margin-bottom:1rem;font-size:13px;color:#92400E;line-height:1.55">
    <strong>Surface scan only</strong> — scanned from live URL. Server-side config, environment variables and database settings cannot be inspected remotely. For a complete analysis use GitHub URL or ZIP upload.
  </div>
  <div class="sticky-bar">
    <div style="display:flex;align-items:center;gap:8px">
      <svg width="22" height="22" viewBox="0 0 400 400" style="flex-shrink:0">
        <rect width="400" height="400" rx="72" fill="#534AB7"/>
        <circle cx="200" cy="158" r="88" fill="#ffffff" fill-opacity="0.1"/>
        <circle cx="200" cy="158" r="66" fill="#ffffff" fill-opacity="0.1"/>
        <polyline points="148,108 200,208 252,108" fill="none" stroke="#ffffff" stroke-width="24" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span style="font-size:14px;font-weight:500;color:var(--pu)">Verilay</span>
      <span style="font-size:12px;color:var(--mut)" id="report-status">Report ready</span>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <button id="btn-save-report" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:12px;cursor:pointer">
        <i class="ti ti-link" style="font-size:13px"></i> Share link
      </button>
      <button id="btn-export-md" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:12px;cursor:pointer">
        <i class="ti ti-download" style="font-size:13px"></i> Export .md
      </button>
      <button id="btn-print" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:12px;cursor:pointer">
        <i class="ti ti-printer" style="font-size:13px"></i> Print / PDF
      </button>
      <button class="btn-sm" id="btn-new">
        <i class="ti ti-plus" style="font-size:14px"></i> New analysis
      </button>
    </div>
  </div>
  <!-- Share link banner — auto-shown after analysis -->
  <div id="share-banner" style="display:none;background:var(--grl);border:0.5px solid var(--grt);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:.75rem;flex-direction:column;gap:8px">
    <div style="display:flex;align-items:center;gap:8px">
      <i class="ti ti-check" style="color:var(--grt);font-size:16px;flex-shrink:0"></i>
      <div style="font-size:13px;font-weight:500;color:var(--grt)">Report saved — share it with anyone</div>
    </div>
    <div style="display:flex;gap:6px;align-items:center">
      <input id="share-url" type="text" readonly style="flex:1;border:0.5px solid var(--grt);border-radius:6px;padding:5px 8px;font-size:12px;font-family:var(--mono);background:white;color:var(--txt)">
      <button id="btn-copy-share" style="font-size:12px;padding:5px 12px;border-radius:20px;background:var(--gr);color:white;border:none;cursor:pointer;flex-shrink:0">Copy link</button>
      <button id="delete-report-btn" onclick="deleteReport()" style="display:none;font-size:12px;padding:5px 10px;border-radius:20px;background:transparent;color:var(--mut);border:0.5px solid var(--bdr);cursor:pointer;flex-shrink:0">Delete report</button>
    </div>
    <div style="font-size:12px;color:var(--grt);opacity:.8">&#x1F512; Report stored securely. Your findings are private and never shared publicly. Delete anytime with the Delete Report button.</div>
    <div id="badge-section" style="display:none;margin-top:4px">
      <div style="font-size:12px;color:var(--grt);margin-bottom:4px;font-weight:500">Add this badge to your GitHub README:</div>
      <input id="badge-code" type="text" readonly style="width:100%;border:0.5px solid var(--grt);border-radius:6px;padding:5px 8px;font-size:12px;font-family:var(--mono);background:white;color:var(--mut)">
    </div>
  </div>

  <div id="report-content"></div>

  <!-- Steps 2+3 loading banner — shown while layers load in background -->
  <div id="steps23-loading" style="display:none;align-items:center;gap:10px;background:var(--pul);border-radius:var(--r);padding:.75rem 1rem;margin-top:.75rem;margin-bottom:.75rem">
    <div style="width:18px;height:18px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>
    <div style="font-size:13px;color:var(--put);font-weight:500" id="steps23-msg">Analysing Auth, Config, Database layers...</div>
  </div>

  <!-- Layers injected here by appendLayers -->
  <div id="layers-container"></div>

  <!-- GitHub star prompt -->
  <div id="star-prompt" style="display:none;text-align:center;margin-bottom:.75rem">
    <a href="https://github.com/ekbm/verilay" target="_blank" style="font-size:13px;color:var(--mut);text-decoration:none">
      ⭐ Found Verilay useful? Star us on GitHub
    </a>
    <div style="display:flex;gap:1rem;justify-content:center;margin-top:.5rem;flex-wrap:wrap">
      <a href="/ask-verilay" style="font-size:12px;color:var(--mut);text-decoration:none">Ask Verilay</a>
      <a href="/about" style="font-size:12px;color:var(--mut);text-decoration:none">About</a>
      <a href="/blog" style="font-size:12px;color:var(--mut);text-decoration:none">Blog</a>
      <a href="/changelog" style="font-size:12px;color:var(--mut);text-decoration:none">Changelog</a>
      <a href="/privacy" style="font-size:12px;color:var(--mut);text-decoration:none">Privacy</a>
      <a href="/terms" style="font-size:12px;color:var(--mut);text-decoration:none">Terms</a>
      <a href="/ai-disclaimer" style="font-size:12px;color:var(--mut);text-decoration:none">AI Disclaimer</a>
      <a href="mailto:moses@verilay.dev?subject=Verilay%20Enquiry" style="font-size:12px;color:var(--mut);text-decoration:none">Contact Moses</a>
    </div>
  </div>

  <!-- Feedback widget -->
  <div id="feedback-widget" style="display:none;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:.75rem;text-align:center">
    <div style="font-size:14px;font-weight:500;margin-bottom:.65rem">Was this analysis helpful?</div>
    <div style="display:flex;gap:8px;justify-content:center;margin-bottom:.5rem">
      <button id="btn-feedback-up" onclick="submitFeedback(true)" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:6px 16px;cursor:pointer;transition:all .15s">👍</button>
      <button id="btn-feedback-down" onclick="submitFeedback(false)" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:6px 16px;cursor:pointer;transition:all .15s">👎</button>
    </div>
    <div id="feedback-text-area" style="display:none;margin-top:.5rem">
      <textarea id="feedback-text" placeholder="What could be better? (optional)" style="width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:8px;font-size:13px;font-family:inherit;resize:vertical;min-height:60px;background:var(--bg);color:var(--txt)"></textarea>
      <input id="feedback-email" type="email" placeholder="Your email — only if you'd like us to follow up (optional)" style="width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:8px;font-size:13px;font-family:inherit;margin-top:6px;box-sizing:border-box;background:var(--bg);color:var(--txt)" />
      <div style="font-size:12px;color:var(--mut);margin-top:4px;text-align:left">We'll only use your email to follow up about this feedback.</div>
      <button onclick="sendFeedbackText()" style="margin-top:6px;font-size:13px;padding:5px 16px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer">Send feedback</button>
    </div>
    <div id="feedback-thanks" style="display:none;font-size:14px;color:var(--mut)">Thanks for the feedback! 🙏</div>
  </div>

  <div class="p2-banner" id="p2-banner">
    <div style="display:flex;align-items:flex-start;gap:12px">
      <i class="ti ti-sparkles" style="font-size:22px;color:var(--pu);flex-shrink:0;margin-top:2px"></i>
      <div style="flex:1">
        <div style="font-size:15px;font-weight:600;color:var(--put);margin-bottom:4px">Part 1 complete - ready for the deep analysis?</div>
        <div style="font-size:13px;color:var(--put);line-height:1.55;margin-bottom:.85rem">Part 2 adds the fix list with effort estimates, second opinion prompts, and security checklist. Takes another 15-20 seconds.</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn-sm" id="btn-p2">Yes, run Part 2</button>
          <button id="btn-skip" style="padding:7px 16px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);font-size:13px;cursor:pointer">Skip for now</button>
        </div>
      </div>
    </div>
  </div>

  <div id="p2-loading" style="display:none;text-align:center;padding:1.5rem;margin-top:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r)">
    <div class="spin" style="width:28px;height:28px;border-width:2.5px;margin-bottom:.75rem"></div>
    <div style="font-size:14px;color:var(--mut)">Running deep analysis...</div>
  </div>

  <div id="p2-results"></div>

  <div class="bottom-cta">
    <div style="font-size:14px;font-weight:500;margin-bottom:.4rem">Analyse another app?</div>
    <div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">Run Verilay on any GitHub repo, ZIP file, or live URL</div>
    <button class="btn-sm" id="btn-new2">
      <i class="ti ti-search" style="font-size:14px"></i> Analyse another app
    </button>
  </div>
</div>

<!-- ── Sample report modal ──────────────────────────────── -->
<div id="sample-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;overflow-y:auto;padding:1.5rem">
  <div style="max-width:680px;margin:0 auto;background:var(--sur);border-radius:var(--r);padding:1.5rem;position:relative">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem">
      <div>
        <div style="font-size:16px;font-weight:600;margin-bottom:2px">Sample Verilay Report</div>
        <div style="font-size:13px;color:var(--mut)">A real analysis of a Lovable-built app — this is what you get</div>
      </div>
      <button id="btn-close-modal" style="padding:6px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;cursor:pointer;font-size:13px;color:var(--mut)">Close</button>
    </div>

    <!-- Production verdict -->
    <div style="background:var(--orl);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px;display:flex;align-items:center;gap:12px">
      <i class="ti ti-alert-triangle" style="font-size:24px;color:var(--ort)"></i>
      <div>
        <div style="font-size:15px;font-weight:600;color:var(--ort)">Needs work before going live</div>
        <div style="font-size:13px;color:var(--mut)">2 critical security issues found that should be fixed before sharing with real users</div>
      </div>
    </div>

    <!-- Stack pills -->
    <div style="background:var(--bg);border-radius:var(--r);padding:1rem;margin-bottom:10px">
      <div style="font-size:12px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Stack detected</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--pul);color:var(--put)">React 18</span>
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--grl);color:var(--grt)">Supabase</span>
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--orl);color:var(--ort)">Vite</span>
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--bll);color:var(--blt)">TypeScript</span>
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:#F1EFE8;color:#444441">Tailwind CSS</span>
        <span style="font-size:12px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--pul);color:var(--put)">shadcn/ui</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:.65rem">
        <div style="background:var(--rdl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--rdt)">2</div><div style="font-size:12px;color:var(--rdt)">critical</div></div>
        <div style="background:var(--orl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--ort)">3</div><div style="font-size:12px;color:var(--ort)">warnings</div></div>
        <div style="background:var(--grl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--grt)">6</div><div style="font-size:12px;color:var(--grt)">passing</div></div>
        <div style="background:var(--bll);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--blt)">C</div><div style="font-size:12px;color:var(--blt)">score</div></div>
      </div>
    </div>

    <!-- Sample layer -->
    <div style="background:var(--bg);border-radius:var(--r);padding:1rem;margin-bottom:10px">
      <div style="font-size:13px;font-weight:600;margin-bottom:.65rem;display:flex;align-items:center;gap:6px">
        <i class="ti ti-shield" style="color:var(--rdt)"></i> Auth layer — 2 issues found
      </div>
      <!-- Expert finding -->
      <div style="background:var(--rdl);border-radius:8px;padding:.65rem .85rem;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;font-size:13px">
        <i class="ti ti-alert-circle" style="color:var(--rdt);font-size:16px;flex-shrink:0;margin-top:1px"></i>
        <div>
          <div style="font-weight:500;margin-bottom:2px;color:var(--rdt)">.env file committed to public GitHub repo</div>
          <div style="color:var(--mut)">Your Supabase credentials are visible to anyone who finds your repo. Rotate your keys immediately in the Supabase dashboard.</div>
        </div>
      </div>
      <div style="background:var(--orl);border-radius:8px;padding:.65rem .85rem;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;font-size:13px">
        <i class="ti ti-alert-triangle" style="color:var(--ort);font-size:16px;flex-shrink:0;margin-top:1px"></i>
        <div>
          <div style="font-weight:500;margin-bottom:2px;color:var(--ort)">JWT tokens have no expiry set</div>
          <div style="color:var(--mut)">Login tokens last forever. A stolen token would give permanent access to any account.</div>
        </div>
      </div>
      <!-- Learner view toggle sample -->
      <div style="background:var(--pul);border-radius:8px;padding:.65rem .85rem;font-size:13px;color:var(--put)">
        <strong>Think of Auth like this:</strong> It's the bouncer at your app's door — checks who you are before letting you in. Right now the bouncer is letting people in with a pass that never expires.
      </div>
    </div>

    <!-- CTA -->
    <div style="text-align:center;padding:.75rem 0 0">
      <div style="font-size:14px;color:var(--mut);margin-bottom:.75rem">This is what Verilay finds in your app — in 30 seconds</div>
      <button id="btn-modal-cta" style="display:inline-flex;align-items:center;gap:7px;padding:10px 24px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:14px;font-weight:500;border:none;cursor:pointer">
        <i class="ti ti-search"></i> Analyse my app now
      </button>
    </div>
  </div>
</div>

</div></main>

<!-- Footer -->
<div style="text-align:center;padding:1.5rem 1rem 2rem;border-top:0.5px solid var(--bdr);margin-top:1rem">
  <a href="https://github.com/ekbm/verilay" target="_blank" style="font-size:13px;color:var(--mut);text-decoration:none">
    ⭐ Found Verilay useful? Star us on GitHub
  </a>
  <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-top:.5rem">
    <a href="/about" style="font-size:12px;color:var(--mut);text-decoration:none">About</a>
    <a href="/blog" style="font-size:12px;color:var(--mut);text-decoration:none">Blog</a>
    <a href="/changelog" style="font-size:12px;color:var(--mut);text-decoration:none">Changelog</a>
    <a href="/privacy" style="font-size:12px;color:var(--mut);text-decoration:none">Privacy</a>
    <a href="/terms" style="font-size:12px;color:var(--mut);text-decoration:none">Terms</a>
    <a href="/ai-disclaimer" style="font-size:12px;color:var(--mut);text-decoration:none">AI Disclaimer</a>
    <a href="mailto:moses@verilay.dev?subject=Verilay%20Enquiry" style="font-size:12px;color:var(--mut);text-decoration:none">Contact Moses</a>
  </div>
</div>

<script>
function toggleBurger() {
  var menu = document.getElementById("burger-menu");
  var btn = document.getElementById("burger-btn");
  if (!menu) return;
  var open = menu.style.display === "block";
  menu.style.display = open ? "none" : "block";
  btn.innerHTML = open ? '<i class="ti ti-menu-2" style="font-size:18px"></i>' : '<i class="ti ti-x" style="font-size:18px"></i>';
}
document.addEventListener("click", function(e) {
  var menu = document.getElementById("burger-menu");
  var btn = document.getElementById("burger-btn");
  if (menu && btn && menu.style.display === "block" && !menu.contains(e.target) && !btn.contains(e.target)) {
    menu.style.display = "none";
    btn.innerHTML = '<i class="ti ti-menu-2" style="font-size:18px"></i>';
  }
});
</script>
</body>
</html>"""

def validate_startup():
    """Validate required environment variables at startup."""
    missing = []
    if not ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY — required for analysis (get from console.anthropic.com)")
    if missing:
        print("\n⚠️  Missing required environment variables:")
        for m in missing:
            print(f"   • {m}")
        print("\nSet these in Railway environment variables or .env file\n")
    else:
        print("✓ Environment validated — all required keys present")

    # ── Paid path ──────────────────────────────────────────────────────────────
    # These are only fatal when the paywall is ON. While it is off they are
    # printed as notes, so the log tells you exactly what is still missing before
    # you flip the switch — rather than finding out from a customer.
    if not _HAS_PAYWALL:
        print("ℹ️  Paid path not loaded — free tool only.")
        return

    problems = []
    if _SECRET_KEY_IS_EPHEMERAL:
        problems.append(
            "SECRET_KEY is not set. Sign-in cookies are signed with a random "
            "per-worker key, so signed-in users WILL be logged out at random. "
            "Set it to a long random string in Railway."
        )
    if not billing._HAS_STRIPE:
        problems.append("The `stripe` package is not installed (add it to requirements.txt).")
    if not billing.STRIPE_SECRET_KEY:
        problems.append("STRIPE_SECRET_KEY is not set — checkout cannot be created.")
    if not billing.STRIPE_WEBHOOK_SECRET:
        problems.append(
            "STRIPE_WEBHOOK_SECRET is not set. Without it the webhook rejects "
            "everything, so payments would never be recorded."
        )
    if not _HAS_SUPABASE:
        problems.append("Supabase is not connected — purchases cannot be stored.")
    try:
        import verilay_accounts as _acc
        if not _acc.configured():
            problems.append("Supabase auth is not configured — nobody can sign in.")
    except Exception as _e:
        problems.append(f"Accounts module unavailable: {_e}")

    if billing.PAYWALL_ENABLED:
        if problems:
            print("\n🚨 PAYWALL IS ON but the paid path is incomplete:")
            for p in problems:
                print(f"   • {p}")
            print("   Turn PAYWALL_ENABLED off until these are fixed.\n")
        else:
            mode = "LIVE — real money" if billing.is_live_key() else "test mode"
            print(f"✓ Paywall ON, {billing.price_label()}, Stripe {mode}")
    else:
        print("✓ Paywall OFF — deep scan not for sale"
              + (f" ({len(problems)} thing(s) still to configure — see /billing-health)"
                 if problems else " (configuration looks complete)"))
        # Say this even with the paywall off. A live key sitting in the environment
        # is one variable away from taking real money, and it is almost always a
        # mistake while the deep scan is still being built — the Stripe dashboard
        # has a test/live toggle and restricted keys belong to whichever mode was
        # showing when you created them.
        if billing.STRIPE_SECRET_KEY:
            if billing.is_live_key():
                print("⚠️  STRIPE_SECRET_KEY is a LIVE key. If you meant test mode, "
                      "create the key with the dashboard toggled to Test — it starts rk_test_.")
            else:
                print("   Stripe key is test mode.")

# ── Wire the deep-scan engine ────────────────────────────────────────────────
# Dependency-injected rather than imported directly by verilay_deepscan, since
# that module cannot import app.py back without a circular import. Placed here,
# not near the top, because it needs functions (analyse_step2, save_report_data,
# etc.) that are only defined by this point in the file.
if _HAS_PAYWALL:
    deepscan.configure(
        fetch_all_files_tarball=fetch_all_files_tarball,
        smart_file_selection=smart_file_selection,
        max_file_chars=MAX_FILE_CHARS,
        github_token=lambda: GITHUB_TOKEN,
        analyse_step1=analyse_step1,
        analyse_step2=analyse_step2,
        analyse_step3=analyse_step3,
        analyse_step4=analyse_step4,
        call_claude_text=call_claude_text,
        parse_flat_response=parse_flat_response,
        scan_repo=scan_repo,
        secret_to_report_dict=to_report_dict,
        secret_to_prompt_block=to_prompt_block,
        check_dependencies=check_dependencies,
        osv_severity_counts=osv_severity_counts,
        osv_to_report_dict=osv_to_report_dict,
        osv_to_prompt_block=osv_to_prompt_block,
        categorise_files=categorise_files,
        grade_from_counts=grade_from_counts,
        save_report_data=save_report_data,
        consume_scan=lambda purchase_id: billing.consume_scan(_sb, purchase_id),
        supabase_client=_sb,
    )

# ── Wire the self-monitoring landing-page teaser ─────────────────────────────
# Unconditional (not gated on _HAS_PAYWALL) — this doesn't touch billing at
# all, just Supabase + the same free-analysis functions above. Should keep
# working even if the paid path is misconfigured.
self_monitor.configure(
    fetch_all_files_tarball=fetch_all_files_tarball,
    smart_file_selection=smart_file_selection,
    max_file_chars=MAX_FILE_CHARS,
    github_token=lambda: GITHUB_TOKEN,
    analyse_step2=analyse_step2,
    analyse_step3=analyse_step3,
    scan_repo=scan_repo,
    secret_to_prompt_block=to_prompt_block,
    check_dependencies=check_dependencies,
    osv_severity_counts=osv_severity_counts,
    osv_to_prompt_block=osv_to_prompt_block,
    grade_from_counts=grade_from_counts,
    supabase_client=_sb,
)

# Run validation on startup (works with both local and Gunicorn)
validate_startup()

if __name__ == "__main__":
    print("🔍 Verilay running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
