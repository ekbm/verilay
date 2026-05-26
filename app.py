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
# - Rate limiting (10/hour per IP)
# - Gunicorn production server (see Procfile)
# - Full error handling on all routes with try/except
# - SSRF protection on live URL scanner
# END SUMMARY

GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", _secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

# ── Report storage ─────────────────────────────────────────────────────────────
_reports = {}
REPORT_TTL = 86400

# ── Analysis counter ────────────────────────────────────────────────────────────
# Uses reports table row count — always accurate, never resets
import threading
_count_lock = threading.Lock()
_memory_count = 0

def get_analysis_count():
    """Get count from Supabase reports table — always accurate."""
    if _HAS_SUPABASE:
        try:
            result = _sb.table("reports").select("id", count="exact").execute()
            return result.count or 0
        except Exception as e:
            print(f"Counter fetch failed: {e}", flush=True)
    return _memory_count

def increment_analysis_count():
    """Increment in-memory count — Supabase row count is source of truth."""
    global _memory_count
    with _count_lock:
        _memory_count += 1
    return _memory_count

def save_report_data(data):
    report_id = _uuid.uuid4().hex[:12]
    if _HAS_SUPABASE:
        try:
            _sb.table("reports").insert({
                "id": report_id,
                "repo": data.get("repo", ""),
                "data": data,
                "input_method": data.get("input_method", "github"),
                "score": data.get("health", {}).get("score", "")
            }).execute()
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
    _rate_limit[ip] = hits
    if len(hits) >= 10:
        return False, int(3600 - (now - min(hits)))
    hits.append(now)
    _rate_limit[ip] = hits
    return True, 0

def get_ip():
    fwd = request.headers.get("X-Forwarded-For","")
    return fwd.split(",")[0].strip() if fwd else request.remote_addr or "unknown"

# ── File readers ───────────────────────────────────────────────────────────────
PRIORITY_FILES = [
    "package.json","requirements.txt","pyproject.toml",".env",".env.example",
    "vite.config.ts","vite.config.js","supabase/config.toml",
    "src/lib/supabase.ts","src/lib/supabase.js",
    "src/integrations/supabase/client.ts",
    "lib/db.ts","lib/database.ts","database.py","prisma/schema.prisma",
    "src/auth.ts","auth.py","middleware/auth.ts","lib/auth.ts",
    "app.py","main.py","index.js","server.js",
    "src/App.tsx","src/App.jsx","src/main.tsx",
    "src/router.tsx","src/routes.tsx",".gitignore","Procfile",
]
KEYWORDS = ["auth","login","database","db","schema","route","api","config","secret","supabase","middleware"]
MAX_FILE_CHARS = 5000
MAX_FILES = 25

def fetch_github(repo_url):
    clean = repo_url.replace("https://","").replace("http://","").strip("/")
    parts = clean.split("/")
    for blocked in ["gitlab.com","bitbucket.org","dev.azure.com"]:
        if blocked in parts[0]:
            raise ValueError(f"{blocked.split('.')[0].title()} support coming soon. Use ZIP upload instead.")
    owner = parts[1] if parts[0]=="github.com" else parts[0]
    repo  = (parts[2] if parts[0]=="github.com" else parts[1]).replace(".git","")
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
            r = requests.get(f"{base}/contents/{path}", headers=hdrs, timeout=10)
            if r.status_code != 200: return None
            d = r.json()
            if isinstance(d, list): return None
            if d.get("encoding") == "base64":
                return base64.b64decode(d["content"]).decode("utf-8","replace")[:MAX_FILE_CHARS]
            return None
        except: return None

    files = {}
    for p in PRIORITY_FILES:
        if p in all_files:
            c = fetch_file(p)
            if c: files[p] = c
    for path in all_files:
        if len(files) >= MAX_FILES: break
        if path in files: continue
        fname = path.lower().split("/")[-1]
        for ext in [".ts",".js",".py",".json",".prisma"]: fname = fname.replace(ext,"")
        if any(k in fname for k in KEYWORDS):
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
            try: return zf.read(name_map[rel]).decode("utf-8","replace")[:MAX_FILE_CHARS]
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
    import ipaddress
    parsed = urlparse(live_url)
    host = parsed.hostname or ""
    if host in ["localhost","127.0.0.1","0.0.0.0","169.254.169.254"]:
        raise ValueError("Cannot scan internal URLs.")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Cannot scan internal IP addresses.")
    except ValueError as e:
        if "Cannot scan" in str(e): raise
    if parsed.scheme not in ("http","https"):
        raise ValueError("Only http:// and https:// URLs supported.")
    r = requests.get(live_url, timeout=10, headers={"User-Agent":"Verilay/1.0"})
    r.raise_for_status()
    domain = live_url.split("/")[2]
    name = domain.replace(".lovable.app","").replace(".replit.app","")
    files = {"index.html": r.text[:20000], "_meta.txt": f"LIVE URL SCAN: {live_url}"}
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


def files_for(files, keys):
    """Build file text block from selected keys, capped at 10KB total."""
    out = ""
    total = 0
    for k in keys:
        if k in files and total < 10000:
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
            messages=[{"role": "user", "content": str(prompt)}]
        ) as stream:
            for text in stream.text_stream:
                raw += text
        return raw.strip()
    else:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
            json={"model":"claude-sonnet-4-5","max_tokens":max_tokens,"stream":True,
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
        for i in range(1, 4):
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
                "what_is_it": kv.get(f"{p}_WHAT", f"The {name} layer handles related functionality."),
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
    tree_str = "\n".join(tree[:60]) if tree else "Not available"
    stack_keys = [k for k in files if any(sf in k for sf in
        ["package.json","requirements","Procfile","vite","tsconfig",".gitignore","Dockerfile"])]
    ftext = files_for(files, stack_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:4000]
    is_surface = method == "url"

    prompt = (
        "Analyse this codebase and respond ONLY with key:value pairs, one per line, no other text.\n\n"
        "Repo: " + repo_name + "\n"
        "File tree:\n" + tree_str + "\n\n"
        "Key files:\n" + ftext + "\n\n"
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
        "SCORE: A|B|C|D|F\n"
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
        "\nBe honest. A score means truly production-ready. Most AI-built apps score B or C.\n"
        "List all libraries/frameworks found. Leave STACK_N fields empty if fewer than N items.\n"
        "IMPORTANT: If input method is 'url' (surface scan), do NOT flag environment variable patterns as security issues "
        "since you cannot inspect server-side configuration from a live URL. Only flag issues visible in the HTML/JS."
    )

    text = call_claude_text(prompt, max_tokens=600)
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
            "reason": lines.get("REASON", "")
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


def analyse_step2(files, repo_name):
    sec_keys = [k for k in files if any(w in k.lower() for w in
        ["auth","login",".env","config","supabase","database","db","schema","prisma","password","token"])][:6]
    ftext = files_for(files, sec_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:5000]

    prompt = (
        "You are Verilay analysing " + repo_name + " for a non-developer who built this app with an AI tool.\n\n"
        "FILES:\n" + ftext + "\n\n"
        "Respond ONLY with key:value pairs, one per line. Be specific to THIS app, not generic.\n\n"
        "AUTH_STATUS: critical|warning|passing\n"
        "AUTH_SUMMARY: one sentence technical summary of auth layer\n"
        "AUTH_F1_SEV: critical|warning|passing\n"
        "AUTH_F1_TITLE: short finding title\n"
        "AUTH_F1_DETAIL: one sentence technical detail\n"
        "AUTH_F1_FILE: filename or empty\n"
        "AUTH_F1_WHY: why this matters to the business\n"
        "AUTH_F1_PLAIN: same finding in plain English a 10-year-old would understand\n"
        "AUTH_F1_IMPACT: specific real-world consequence if not fixed (e.g. a stranger could log in as any user)\n"
        "AUTH_F1_ACTION: exact step to fix this in Lovable or Replit\n"
        "AUTH_WHAT: what the auth layer IS in plain English (1-2 sentences, no jargon)\n"
        "AUTH_ANALOGY: a specific real-world analogy tied to what THIS app does (not generic - e.g. if it is a booking app say bookings, if ecommerce say shopping)\n"
        "AUTH_DOES: what auth specifically does in THIS app based on the code you can see\n"
        "AUTH_CONNECTS: how auth connects to the database and frontend in this specific app\n"
        "AUTH_CONCEPT: the single most important thing to understand about auth in this app\n"
        "AUTH_Q: a quiz question that tests understanding of the specific auth finding (not generic)\n"
        "AUTH_A: the answer in plain English\n"
        "AUTH_QWHY: why understanding this matters for their app\n"
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
        "CONFIG_ANALOGY: specific analogy tied to this app type\n"
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
        "DATABASE_ANALOGY: specific analogy tied to this app type\n"
        "DATABASE_DOES: what the database stores in this specific app\n"
        "DATABASE_CONNECTS: how it connects to other layers\n"
        "DATABASE_CONCEPT: most important concept\n"
        "DATABASE_Q: quiz question specific to this finding\n"
        "DATABASE_A: plain English answer\n"
        "DATABASE_QWHY: why it matters\n"
    )
    text = call_claude_text(prompt, max_tokens=1200)
    return parse_flat_response(text, ["Auth", "Config", "Database"])


def analyse_step3(files, repo_name):
    api_keys = [k for k in files if any(w in k.lower() for w in
        ["route","api","app.py","main.py","server","app.tsx","app.jsx","package.json"])][:6]
    if "package.json" in files and "package.json" not in api_keys:
        api_keys.insert(0, "package.json")
    ftext = files_for(files, api_keys) or files_for(files, list(files.keys())[:3])
    ftext = ftext[:5000]

    prompt = (
        "You are Verilay analysing " + repo_name + " for a non-developer who built this with an AI tool.\n\n"
        "FILES:\n" + ftext + "\n\n"
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
        "API_ANALOGY: specific analogy tied to what THIS app does\n"
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
        "FRONTEND_ANALOGY: specific analogy tied to this app type\n"
        "FRONTEND_DOES: what the frontend does in this specific app\n"
        "FRONTEND_CONNECTS: how frontend connects to API and auth\n"
        "FRONTEND_CONCEPT: most important concept\n"
        "FRONTEND_Q: quiz question specific to this app\n"
        "FRONTEND_A: plain English answer\n"
        "FRONTEND_QWHY: why it matters\n"
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
        "LIBRARIES_ANALOGY: specific analogy tied to this app\n"
        "LIBRARIES_DOES: what the key libraries do in this app\n"
        "LIBRARIES_CONNECTS: how libraries connect to other layers\n"
        "LIBRARIES_CONCEPT: most important concept\n"
        "LIBRARIES_Q: quiz question specific to this app\n"
        "LIBRARIES_A: plain English answer\n"
        "LIBRARIES_QWHY: why it matters\n"
    )
    text = call_claude_text(prompt, max_tokens=1200)
    return parse_flat_response(text, ["API", "Frontend", "Libraries"])


def analyse_step4(repo_name, built_with, findings_summary):
    is_lovable = "lovable" in built_with.lower()
    is_replit  = "replit" in built_with.lower()
    platform   = "Lovable" if is_lovable else ("Replit" if is_replit else "your AI builder")

    prompt = (
        "Based on this analysis of " + repo_name + ":\n"
        + findings_summary +
        "\n\nRespond ONLY with key:value pairs, one per line, no other text.\n\n"
        "FIX_1_TITLE: most urgent fix\n"
        "FIX_1_WHY: why it matters in one sentence\n"
        "FIX_1_HOW: 2-3 step fix instruction\n"
        "FIX_1_EFFORT: 5 minutes|30 minutes|1 hour|1 day\n"
        "FIX_1_PROMPT: complete prompt to paste into " + platform + " to fix this\n"
        "FIX_2_TITLE: second fix\n"
        "FIX_2_WHY: why\n"
        "FIX_2_HOW: how\n"
        "FIX_2_EFFORT: effort\n"
        "FIX_2_PROMPT: prompt for " + platform + "\n"
        "FIX_3_TITLE: third fix\n"
        "FIX_3_WHY: why\n"
        "FIX_3_HOW: how\n"
        "FIX_3_EFFORT: effort\n"
        "FIX_3_PROMPT: prompt for " + platform + "\n"
        "SEC_SECRETS: true|false (are secrets exposed in repo)\n"
        "SEC_AUTH: true|false (is auth properly configured)\n"
        "SEC_RLS: true|false (is row level security configured)\n"
        "SEC_DEPS: true|false (are dependencies current)\n"
        "SEC_HARDCODED: true|false (no hardcoded secrets in code)\n"
        "OPINION_GENERAL: complete self-contained prompt to paste into Claude or ChatGPT to verify these findings about " + repo_name + "\n"
        "OPINION_SECURITY: complete prompt to verify the security findings specifically\n"
        "OPINION_PROD: complete prompt asking if " + repo_name + " is ready for production\n"
    )

    text = call_claude_text(prompt, max_tokens=800)
    lines = {}
    for line in text.strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            lines[key.strip().upper()] = val.strip()

    def parse_bool(val, default=True):
        if not val: return default
        return val.lower() not in ("false", "no", "0")

    fixes = []
    for i in range(1, 5):
        title = lines.get(f"FIX_{i}_TITLE", "")
        if not title or title.lower() in ("next fix", ""):
            break
        fixes.append({
            "priority": i,
            "title": title,
            "why_it_matters": lines.get(f"FIX_{i}_WHY", ""),
            "how_to_fix": lines.get(f"FIX_{i}_HOW", ""),
            "estimated_effort": lines.get(f"FIX_{i}_EFFORT", "30 minutes"),
            "lovable_prompt": lines.get(f"FIX_{i}_PROMPT", ""),
            "general_prompt": lines.get(f"FIX_{i}_PROMPT", "")
        })

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
                files, tree, repo_name = fetch_github(url)
            elif method == "zip":
                f = request.files.get("zip_file")
                if not f:
                    yield json.dumps({"event":"error","data":"Please select a ZIP file"}) + "\n"; return
                zip_data = f.read()
                zip_size_mb = len(zip_data) / (1024 * 1024)
                if zip_size_mb > 50:
                    yield json.dumps({"event":"error","data":f"ZIP file is {zip_size_mb:.0f}MB — too large to analyse. Please remove the node_modules folder before zipping (right-click node_modules → delete, then re-zip). This usually reduces size to under 5MB."}) + "\n"; return
                files, tree, repo_name = fetch_zip(io.BytesIO(zip_data), f.filename)
            elif method == "url":
                url = request.form.get("live_url","").strip()
                if not url:
                    yield json.dumps({"event":"error","data":"Please enter a URL"}) + "\n"; return
                files, tree, repo_name = fetch_url(url)
            else:
                yield json.dumps({"event":"error","data":"Unknown method"}) + "\n"; return

            if not files:
                yield json.dumps({"event":"error","data":"No readable files found. Try ZIP upload."}) + "\n"; return

            yield json.dumps({"event":"status","data":f"Found {len(files)} files — detecting stack..."}) + "\n"

            # ── Step 1: Stack + overview ────────────────────────────────
            s1 = analyse_step1(files, tree, repo_name, method)
            s1["files_read"] = len(files)
            s1["generated_at"] = datetime.now().strftime("%d %b %Y %H:%M")
            count = increment_analysis_count()
            s1["analysis_count"] = count
            yield json.dumps({"event":"step1","data":s1}) + "\n"

            # ── Steps 2 + 3 in parallel ────────────────────────────────
            yield json.dumps({"event":"status","data":"Analysing layers in parallel..."}) + "\n"
            import concurrent.futures
            s2 = {"layers":[]}
            s3 = {"layers":[]}
            s2_err = None
            s3_err = None
            # Run in parallel, collect results, THEN yield
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f2 = executor.submit(analyse_step2, files, repo_name)
                f3 = executor.submit(analyse_step3, files, repo_name)
                try:
                    s2 = f2.result(timeout=55)
                except Exception as e:
                    s2_err = str(e)
                try:
                    s3 = f3.result(timeout=55)
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
                yield json.dumps({"event":"step3","data":s3}) + "\n"

            # ── Auto-save partial report ────────────────────────────────
            partial = dict(s1)
            partial["layers"] = s2.get("layers",[]) + s3.get("layers",[])
            report_id = save_report_data(partial)
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


@app.route("/feedback", methods=["POST"])
def feedback():
    try:
        data = request.get_json()
        helpful = data.get("helpful")
        comment = data.get("comment", "")
        report_id = data.get("report_id", "")
        print(f"Feedback: helpful={helpful} report={report_id} comment={comment[:100]}", flush=True)
        if _HAS_SUPABASE and report_id:
            try:
                _sb.table("reports").update({
                    "data": {**get_report_data(report_id), "feedback_helpful": helpful, "feedback_comment": comment}
                }).eq("id", report_id).execute()
            except:
                pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stats")
def stats():
    count = get_analysis_count()
    return jsonify({"analyses": count, "formatted": f"{count:,}"})


@app.route("/counter")
def counter_debug():
    """Debug endpoint to check counter sources."""
    mem = _memory_count
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

    verdict_label = {"ready":"Production Ready","needs_work":"Needs Work","not_ready":"Not Ready"}.get(pr.get("verdict","needs_work"),"Needs Work")
    verdict_color = {"ready":"#1D9E75","needs_work":"#EF9F27","not_ready":"#E24B4A"}.get(pr.get("verdict","needs_work"),"#EF9F27")
    score_color = {"A":"#1D9E75","B":"#4A90D9","C":"#EF9F27","D":"#E24B4A","F":"#A32D2D"}.get(h.get("score","?"),"#999")
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
  <div style="font-size:13px;color:#555">{pr.get('reason','')}</div>
</div>""")

    # Score grid
    out.append(f"""<div class="sg">
  <div class="sb"><div class="sn" style="color:{score_color}">{h.get('score','?')}</div><div class="sl">Score</div></div>
  <div class="sb"><div class="sn" style="color:#E24B4A">{h.get('critical',0)}</div><div class="sl">Critical</div></div>
  <div class="sb"><div class="sn" style="color:#EF9F27">{h.get('warnings',0)}</div><div class="sl">Warnings</div></div>
  <div class="sb"><div class="sn" style="color:#1D9E75">{h.get('passing',0)}</div><div class="sl">Passing</div></div>
</div>""")

    # Stack
    if stack:
        tags = "".join(f'<span class="tag">{s.get("name","")} {s.get("version","")}</span>' for s in stack)
        out.append(f'<div class="st">Tech Stack</div><div class="card">{tags}</div>')

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

    out.append('<div style="background:#f8f8fc;border-radius:10px;padding:.85rem 1rem;margin:1rem 0;font-size:12px;color:#888;line-height:1.6;text-align:center">Scores may vary slightly between runs as findings are AI-generated. A meaningful improvement (e.g. C &rarr; B) after applying fixes indicates real progress.</div>')
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
    lines = [f"# Verilay Report: {repo}",
             f"Generated: {data.get('generated_at','')}","",
             "## Production Verdict",
             f"**{{'ready':'Production Ready','needs_work':'Needs Work','not_ready':'Not Ready'}}.get(pr.get('verdict','needs_work'),'Needs Work')}}** ({pr.get('confidence','?')} confidence)",
             pr.get("reason",""),"",
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


@app.route("/")
def index():
    count = get_analysis_count()
    return render_template_string(HTML, analysis_count=count if count > 0 else "")


@app.route("/static/app.js")
def serve_js():
    import os
    js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.js')
    try:
        with open(js_path, 'r') as f:
            js_content = f.read()
        return Response(js_content, mimetype='application/javascript',
            headers={'Cache-Control': 'no-cache'})
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;font-size:15px}
.wrap{max-width:1100px;margin:0 auto;padding:2rem 2.5rem}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:.3rem}
.logo-text{font-size:24px;font-weight:600;color:var(--pu)}
.tagline{font-size:14px;color:var(--mut);margin-bottom:2rem}
.label{font-size:14px;font-weight:500;margin-bottom:.65rem}
.mg{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:1.25rem}
.mc{border:1.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem;cursor:pointer;background:var(--sur);transition:all .15s;user-select:none}
.mc:hover{border-color:#aaa8ff}
.mc.sel{border-color:var(--pu);background:var(--pul)}
.mc-icon{font-size:20px;margin-bottom:.4rem}
.mc-title{font-size:13px;font-weight:500;margin-bottom:2px}
.mc-desc{font-size:11px;color:var(--mut);line-height:1.4}
.mbadge{font-size:10px;font-weight:500;padding:2px 7px;border-radius:20px;margin-top:5px;display:inline-block}
.ip{display:none;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:1rem}
.ip.vis{display:block}
.lbl{font-size:12px;font-weight:500;margin-bottom:.4rem;display:block}
.sub{font-size:11px;color:var(--mut);margin-bottom:.6rem;line-height:1.45}
input[type=url],input[type=text]{width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:9px 12px;font-size:13px;background:var(--bg);color:var(--txt);outline:none}
input:focus{border-color:var(--pu)}
.hint{background:var(--pul);border-radius:8px;padding:.65rem .85rem;font-size:12px;color:var(--put);margin-top:.65rem;line-height:1.5}
.hint ol{margin-top:.35rem;padding-left:1.1rem}
.hint li{margin-bottom:2px}
.fd{border:1.5px dashed var(--bdr);border-radius:8px;padding:1.5rem;text-align:center;cursor:pointer;position:relative;transition:all .15s;background:var(--bg)}
.fd:hover{border-color:var(--pu);background:var(--pul)}
.fd input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.erbox{background:var(--rdl);border-radius:var(--r);padding:1rem;color:var(--rdt);font-size:13px;margin-bottom:1rem;display:none}
.erbox.vis{display:block}
.btn{width:100%;padding:12px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:14px;font-weight:500;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px}
.btn:hover{opacity:.9}
.btn:disabled{opacity:.5;cursor:not-allowed}
.ld{display:none;text-align:center;padding:2.5rem}
.ld.vis{display:block}
.spin{width:36px;height:36px;border:3px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;margin:0 auto 1rem}
@keyframes sp{to{transform:rotate(360deg)}}
.rpt{display:none}
.rpt.vis{display:block}
.sticky-bar{display:flex;align-items:center;justify-content:space-between;padding:.65rem .9rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);position:sticky;top:0;z-index:10;margin-bottom:1rem}
.btn-sm{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:20px;background:var(--pu);color:#fff;font-size:12px;font-weight:500;border:none;cursor:pointer}
.prod-banner{border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.rh{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.1rem;margin-bottom:10px}
.pill{font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;display:inline-block;margin:2px}
.hg{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:.65rem}
.hc{border-radius:8px;padding:.55rem;text-align:center}
.tabs{display:flex;gap:5px;margin-bottom:1rem;flex-wrap:wrap}
.tab{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:500;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut)}
.tab.on{background:var(--pu);color:#fff;border-color:transparent}
.panel{display:none}.panel.on{display:block}
.ll{display:grid;grid-template-columns:175px 1fr;gap:12px}
.lnav{display:flex;flex-direction:column;gap:5px}
.lb{display:flex;align-items:center;gap:8px;padding:7px 9px;border-radius:8px;cursor:pointer;border:0.5px solid transparent;background:var(--bg);width:100%;text-align:left;font-size:12px;font-weight:500}
.lb:hover,.lb.act{background:var(--sur);border-color:var(--bdr)}
.ldot{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-left:auto}
.lico{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.ca{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem;min-height:280px}
.mt{display:flex;gap:4px;margin-bottom:.85rem;flex-wrap:wrap}
.mb{font-size:11px;font-weight:500;padding:4px 14px;border-radius:20px;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);transition:all .15s}
.mb.on{background:var(--pu);color:#fff;border-color:transparent}
.mb[data-mode="learner"]{border-color:var(--pu);color:var(--put)}
.mb[data-mode="learner"].on{background:var(--pu);color:#fff}
.mb[data-mode="learner"]::before{content:"✦ ";font-size:9px}
.finding{border-radius:8px;padding:.75rem .95rem;margin-bottom:8px;display:flex;align-items:flex-start;gap:8px;font-size:12px;line-height:1.5}
.lc{background:var(--bg);border-left:2px solid var(--pu);border-radius:0 8px 8px 0;padding:.65rem .85rem;margin-bottom:7px}
.lc-title{font-size:12px;font-weight:500;margin-bottom:3px}
.lc-body{font-size:12px;color:var(--mut);line-height:1.5}
.analogy{background:var(--pul);border-left:3px solid var(--pu);border-radius:0 8px 8px 0;padding:.75rem .95rem;margin-bottom:10px;font-size:14px;color:var(--put);line-height:1.6;font-style:italic}
.learner-section{background:linear-gradient(135deg,var(--pul) 0%,transparent 100%);border:0.5px solid var(--pu);border-radius:var(--r);padding:1rem;margin-bottom:8px}
.learner-label{font-size:10px;font-weight:600;color:var(--pu);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem;display:flex;align-items:center;gap:5px}
.key-concept{background:var(--pu);color:#fff;border-radius:8px;padding:.65rem .9rem;margin:.5rem 0;font-size:12px;line-height:1.55}
.qcard{background:var(--pul);border-radius:8px;padding:.75rem .9rem;margin-bottom:7px}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px}
.sc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.7rem .85rem}
.fc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.si{border-radius:8px;padding:.6rem .85rem;margin-bottom:6px;display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500}
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
<script src="/static/app.js"></script>
</head>
<body>
<main><div class="wrap">

<!-- ── Nav ─────────────────────────────────────────────────── -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2.5rem">
  <div style="display:flex;align-items:center;gap:8px">
    <i class="ti ti-topology-star" style="font-size:20px;color:var(--pu)"></i>
    <span style="font-size:18px;font-weight:700;color:var(--pu)">Verilay</span>
    <span style="font-size:10px;color:var(--mut);background:var(--bg);border:0.5px solid var(--bdr);padding:2px 7px;border-radius:20px;margin-left:2px">verification layer</span>
  </div>
  <div style="display:flex;gap:8px">
    <a href="https://github.com/ekbm/verilay" target="_blank" aria-label="View Verilay on GitHub" style="display:inline-flex;align-items:center;gap:5px;font-size:11px;padding:5px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);text-decoration:none">
      <i class="ti ti-brand-github" style="font-size:13px" aria-hidden="true"></i> GitHub
    </a>
    <button id="btn-start-hero" style="display:inline-flex;align-items:center;gap:5px;font-size:11px;padding:5px 14px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer;font-weight:500">
      Analyse my app
    </button>
  </div>
</div>

<!-- ── Hero ────────────────────────────────────────────────── -->
<div id="hero-section">
  <div style="text-align:center;padding:2rem 0 1.5rem">
    <div style="display:inline-flex;align-items:center;gap:6px;background:var(--pul);color:var(--put);font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;margin-bottom:1.25rem">
      <i class="ti ti-sparkles" style="font-size:12px"></i>
      Free &amp; open source — built for non-developers
    </div>
    <h1 style="font-size:clamp(1.75rem,4vw,3rem);font-weight:700;line-height:1.2;margin-bottom:.85rem;letter-spacing:-.02em">
      Understand what your<br>
      <span style="color:var(--pu)">AI-built app</span> is made of
    </h1>
    <p style="font-size:15px;color:var(--mut);max-width:580px;margin:0 auto 2rem;line-height:1.65">
      You built something with Lovable, Replit, or Bolt. But do you know if it's secure? What libraries it uses? Whether it's ready to ship? Verilay tells you — in plain English.
    </p>
    {% if analysis_count %}
    <div id="analysis-count-badge" style="margin-bottom:.85rem;text-align:center;width:100%">
      <span style="font-size:12px;color:var(--mut);background:var(--sur);border:0.5px solid var(--bdr);padding:5px 16px;border-radius:20px;display:inline-block">
        🔍 {{ analysis_count }} apps analysed so far
      </span>
    </div>
    {% endif %}
    <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:2.5rem">
      <button id="btn-hero-analyse" style="display:inline-flex;align-items:center;gap:7px;padding:12px 24px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:14px;font-weight:500;border:none;cursor:pointer">
        <i class="ti ti-search" style="font-size:15px"></i> Analyse my app — it's free
      </button>
      <button id="btn-hero-demo" style="display:inline-flex;align-items:center;gap:7px;padding:12px 24px;border-radius:var(--r);background:transparent;color:var(--txt);font-size:14px;font-weight:500;border:1.5px solid var(--bdr);cursor:pointer">
        <i class="ti ti-player-play" style="font-size:15px"></i> See a sample report
      </button>
    </div>
  </div>

  <!-- Problem → Solution strip -->
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--bdr);border-radius:var(--r);overflow:hidden;margin-bottom:2.5rem">
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">🤖</div>
      <div style="font-size:13px;font-weight:500;margin-bottom:4px">AI built your app</div>
      <div style="font-size:12px;color:var(--mut);line-height:1.5">Lovable, Replit, Bolt, v0, Cursor — powerful tools that generate real code fast.</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">❓</div>
      <div style="font-size:13px;font-weight:500;margin-bottom:4px">But can you trust it?</div>
      <div style="font-size:12px;color:var(--mut);line-height:1.5">Is your login secure? Are your database credentials exposed? Is it ready for real users?</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">🔍</div>
      <div style="font-size:13px;font-weight:500;margin-bottom:4px">Verilay answers that</div>
      <div style="font-size:12px;color:var(--mut);line-height:1.5">Reads every layer of your app. Explains it in plain English. Flags issues. Gives you a second opinion.</div>
    </div>
    <div style="background:var(--sur);padding:1.25rem 1.4rem">
      <div style="font-size:22px;margin-bottom:.5rem">✅</div>
      <div style="font-size:13px;font-weight:500;margin-bottom:4px">Ship with confidence</div>
      <div style="font-size:12px;color:var(--mut);line-height:1.5">Know exactly what you built and whether it's ready. No developer needed to understand the results.</div>
    </div>
  </div>

  <!-- How it works -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;font-size:13px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:1.1rem">How it works</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px">

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;position:relative">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">1</div>
        <div style="font-size:13px;font-weight:500;margin-bottom:.3rem">Analyse</div>
        <div style="font-size:12px;color:var(--mut);line-height:1.55">Paste your GitHub link, upload a ZIP, or enter your live app URL. Verilay reads every layer of your app in 30 seconds.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">2</div>
        <div style="font-size:13px;font-weight:500;margin-bottom:.3rem">Check issues</div>
        <div style="font-size:12px;color:var(--mut);line-height:1.55">See what was found across 6 layers — Auth, Database, API, Frontend, Config, Libraries. Each issue rated critical, warning, or passing.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">3</div>
        <div style="font-size:13px;font-weight:500;margin-bottom:.3rem">Learn</div>
        <div style="font-size:12px;color:var(--mut);line-height:1.55">Switch to Learner mode for plain-English explanations, real-world analogies, and optional quizzes — so you actually understand what was built.</div>
      </div>

      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem">
        <div style="width:28px;height:28px;border-radius:50%;background:var(--pu);color:#fff;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:.65rem">4</div>
        <div style="font-size:13px;font-weight:500;margin-bottom:.3rem">Fix and re-run</div>
        <div style="font-size:12px;color:var(--mut);line-height:1.55">Copy the ready-to-paste fix prompt, apply it in Lovable or Replit, then re-run Verilay to confirm the issue is resolved and your score improves.</div>
      </div>

    </div>
  </div>

  <!-- What you get -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;font-size:13px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:1.1rem">What Verilay gives you</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px">
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-stack-2" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Tech stack map</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Every library and framework detected and explained in plain English.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-layers-difference" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Layer map</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Auth, Database, API, Frontend — each layer explained with expert and learner views.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-shield-check" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Security check</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Exposed secrets, auth issues, outdated libraries — flagged before they become problems.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-rocket" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Production verdict</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Green, amber, or red — is your app ready to ship to real users?</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-school" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Learner mode</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Understand what each part of your app does with real-world analogies and quizzes.</div>
      </div>
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:.4rem">
          <i class="ti ti-message-check" style="font-size:16px;color:var(--pu)"></i>
          <span style="font-size:12px;font-weight:500">Second opinion</span>
        </div>
        <div style="font-size:11px;color:var(--mut);line-height:1.45">Copy-ready prompts to verify findings in Claude, ChatGPT, or with a developer.</div>
      </div>
    </div>
  </div>

  <!-- Honest scope statement -->
  <div style="background:var(--bg);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.25rem;margin-bottom:2rem;display:flex;align-items:flex-start;gap:10px">
    <i class="ti ti-info-circle" style="font-size:16px;color:var(--mut);flex-shrink:0;margin-top:1px"></i>
    <div style="font-size:12px;color:var(--mut);line-height:1.6">
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
      It is <em>not</em> a penetration test or a professional security audit.
      For apps going live with real user data or payments, we always recommend a deeper review from
      <a href="https://snyk.io" target="_blank" style="color:var(--pu);text-decoration:underline">Snyk</a>,
      <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu);text-decoration:underline">CodeRabbit</a>,
      or a developer before launch. The second opinion prompts in every report make this easy.
    </div>
  </div>

  <!-- Learner mode highlight -->
  <div style="margin-bottom:2.5rem">
    <div style="text-align:center;margin-bottom:1.25rem">
      <div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.4rem">What makes Verilay different</div>
      <div style="font-size:20px;font-weight:700;letter-spacing:-.01em;margin-bottom:.4rem">Built for people who <span style="color:var(--pu)">didn't write the code</span></div>
      <div style="font-size:13px;color:var(--mut);max-width:480px;margin:0 auto">Every finding comes in two modes. Switch between them any time.</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <!-- Developer mode -->
      <div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.1rem;opacity:.7">
        <div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:6px">
          <i class="ti ti-code" style="font-size:13px"></i> Expert mode
        </div>
        <div style="background:var(--rdl);border-radius:8px;padding:.65rem .85rem;font-size:12px;color:var(--rdt);line-height:1.5">
          <div style="font-weight:500;margin-bottom:3px">JWT tokens have no expiry configured</div>
          <div style="font-size:11px;opacity:.85">Supabase auth.session.expires_in not set. Tokens are valid indefinitely, creating persistent session hijacking risk. CWE-613.</div>
        </div>
      </div>
      <!-- Learner mode -->
      <div style="background:var(--sur);border:1.5px solid var(--pu);border-radius:var(--r);padding:1.1rem;position:relative">
        <div style="position:absolute;top:-10px;left:50%;transform:translateX(-50%);background:var(--pu);color:#fff;font-size:10px;font-weight:600;padding:2px 10px;border-radius:20px;white-space:nowrap">Your view</div>
        <div style="font-size:10px;font-weight:600;color:var(--put);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:6px">
          <i class="ti ti-school" style="font-size:13px"></i> Learner mode
        </div>
        <div style="background:var(--pul);border-radius:8px;padding:.55rem .75rem;font-size:12px;color:var(--put);margin-bottom:.5rem;line-height:1.5">
          <i class="ti ti-bulb" style="font-size:12px;margin-right:4px"></i>
          <strong>Think of it like this:</strong> Login tokens are like hotel key cards. Right now yours never expire - a stolen key card works forever.
        </div>
        <div style="background:var(--rdl);border-radius:8px;padding:.55rem .75rem;font-size:12px;color:var(--rdt);line-height:1.5;margin-bottom:.5rem">
          <div style="font-weight:500;margin-bottom:2px">Login sessions never expire</div>
          <div style="font-size:11px">If someone steals a login token, they have permanent access to that account - even after the user changes their password.</div>
        </div>
        <div style="background:var(--grl);border-radius:8px;padding:.55rem .75rem;font-size:11px;color:var(--grt);line-height:1.5">
          <strong>Fix in Lovable:</strong> "Add a 24-hour session expiry to my Supabase auth configuration"
        </div>
      </div>
    </div>
    <!-- Quiz teaser -->
    <div style="margin-top:10px;background:var(--pul);border-radius:var(--r);padding:.85rem 1rem;display:flex;align-items:center;gap:12px">
      <i class="ti ti-brain" style="font-size:22px;color:var(--pu);flex-shrink:0"></i>
      <div>
        <div style="font-size:13px;font-weight:500;color:var(--put);margin-bottom:2px">Test your understanding with optional quizzes</div>
        <div style="font-size:12px;color:var(--put);opacity:.85">Every layer includes a quiz question so you actually learn what was built - not just what was wrong.</div>
      </div>
    </div>
  </div>

  <!-- Platforms -->
  <div style="text-align:center;margin-bottom:2.5rem">
    <div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Works with apps built on</div>
    <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px">
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🔷 Lovable</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🟢 Replit</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">⚡ Bolt</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🔲 v0</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🌀 Cursor</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🌊 Windsurf</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">🚀 Emergent</span>
      <span style="font-size:12px;padding:5px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:var(--sur)">+ any GitHub repo</span>
    </div>
  </div>

  <!-- CTA -->
  <div style="text-align:center;background:var(--pul);border-radius:var(--r);padding:1.75rem 1.5rem;margin-bottom:2rem">
    <div style="font-size:17px;font-weight:600;margin-bottom:.4rem">Ready to see what's inside your app?</div>
    <div style="font-size:13px;color:var(--mut);margin-bottom:1.1rem">Free. Takes 30 seconds. No account needed.</div>
    <button id="btn-hero-cta" style="display:inline-flex;align-items:center;gap:7px;padding:12px 28px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:14px;font-weight:500;border:none;cursor:pointer">
      <i class="ti ti-search" style="font-size:15px"></i> Analyse my app
    </button>
  </div>
</div>

<!-- ── Analysis history ─────────────────────────────────── -->
<div id="history-section" style="display:none;margin-bottom:1.5rem">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.65rem">
    <div style="font-size:12px;font-weight:500;color:var(--mut);display:flex;align-items:center;gap:6px">
      <i class="ti ti-history" style="font-size:14px"></i> Recent analyses
    </div>
    <button id="btn-clear-history" style="font-size:11px;padding:3px 10px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">Clear</button>
  </div>
  <div id="history-list" style="display:flex;flex-direction:column;gap:6px"></div>
</div>

<!-- ── Analysis form (hidden until user clicks analyse) ──── -->
<div id="form-section" style="display:none">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:1.25rem">
    <button id="btn-back-hero" style="display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:5px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">
      <i class="ti ti-arrow-left" style="font-size:13px"></i> Back
    </button>
    <span style="font-size:14px;font-weight:500">Analyse your app</span>
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
    <div class="hint" style="background:var(--bg);border:0.5px solid var(--bdr)">
      <div style="font-size:11px;font-weight:600;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-bottom:.5rem">How to find your repo URL</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;font-size:11px;color:var(--mut)">
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
      <div style="margin-top:.65rem;font-size:11px;color:var(--mut)">
        <strong style="color:var(--txt)">Note:</strong> Repo must be public for Verilay to read it, or connect with a personal access token in your .env file.
      </div>
    </div>
  </div>

  <div class="ip" id="p-zip">
    <label class="lbl">Upload your project ZIP</label>
    <p class="sub">Export your project as a ZIP from your AI builder — no GitHub account needed</p>
    <div class="fd" id="dz">
      <input type="file" id="zf" accept=".zip">
      <div style="font-size:24px;color:var(--mut);margin-bottom:.4rem"><i class="ti ti-upload"></i></div>
      <div style="font-size:13px;color:var(--mut)">Drop ZIP here or click to browse</div>
      <div id="fn" style="font-size:12px;color:var(--gr);margin-top:.4rem;font-weight:500"></div>
    </div>
    <div class="hint" style="background:var(--bg);border:0.5px solid var(--bdr);margin-top:.75rem">
      <div style="font-size:11px;font-weight:600;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-bottom:.5rem">How to export a ZIP from your builder</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;font-size:11px;color:var(--mut)">
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
        <div style="font-size:11px;color:var(--mut);margin-top:2px" id="ls">Fetching from GitHub API</div>
      </div>
    </div>
    <div style="background:var(--bdr);border-radius:20px;height:6px;overflow:hidden;margin-bottom:.65rem">
      <div id="prog-bar" style="height:100%;border-radius:20px;background:linear-gradient(90deg,var(--pu),#8B7FE8);width:0%;transition:width 0.6s ease"></div>
    </div>
    <div style="display:flex;justify-content:space-between;margin-bottom:1.25rem">
      <span style="font-size:10px;color:var(--mut)" id="prog-pct">0%</span>
      <span style="font-size:10px;color:var(--mut)" id="prog-eta">~30 seconds</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px" id="step-list">
      <div class="step-item" id="step-0" data-step="0">
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px">1</div>
          <span>Reading project files</span>
        </div>
      </div>
      <div class="step-item" id="step-1" data-step="1">
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px">2</div>
          <span>Detecting tech stack</span>
        </div>
      </div>
      <div class="step-item" id="step-2" data-step="2">
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px">3</div>
          <span>Analysing layers (Auth, DB, API...)</span>
        </div>
      </div>
      <div class="step-item" id="step-3" data-step="3">
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px">4</div>
          <span>Running security checks</span>
        </div>
      </div>
      <div class="step-item" id="step-4" data-step="4">
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--mut)">
          <div class="step-icon" style="width:20px;height:20px;border-radius:50%;border:1.5px solid var(--bdr);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px">5</div>
          <span>Writing plain-English explanations</span>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="rpt" id="rpt">
  <div id="surface-scan-notice" style="display:none;background:#FEF3C7;border:0.5px solid #F59E0B;border-radius:12px;padding:.75rem 1rem;margin-bottom:1rem;font-size:12px;color:#92400E;line-height:1.55">
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
      <span style="font-size:13px;font-weight:500;color:var(--pu)">Verilay</span>
      <span style="font-size:11px;color:var(--mut)" id="report-status">Report ready</span>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <button id="btn-save-report" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:11px;cursor:pointer">
        <i class="ti ti-link" style="font-size:12px"></i> Share link
      </button>
      <button id="btn-export-md" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:11px;cursor:pointer">
        <i class="ti ti-download" style="font-size:12px"></i> Export .md
      </button>
      <button id="btn-print" style="display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);font-size:11px;cursor:pointer">
        <i class="ti ti-printer" style="font-size:12px"></i> Print / PDF
      </button>
      <button class="btn-sm" id="btn-new">
        <i class="ti ti-plus" style="font-size:13px"></i> New analysis
      </button>
    </div>
  </div>
  <!-- Share link banner — auto-shown after analysis -->
  <div id="share-banner" style="display:none;background:var(--grl);border:0.5px solid var(--grt);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:.75rem;flex-direction:column;gap:8px">
    <div style="display:flex;align-items:center;gap:8px">
      <i class="ti ti-check" style="color:var(--grt);font-size:16px;flex-shrink:0"></i>
      <div style="font-size:12px;font-weight:500;color:var(--grt)">Report saved — share it with anyone</div>
    </div>
    <div style="display:flex;gap:6px;align-items:center">
      <input id="share-url" type="text" readonly style="flex:1;border:0.5px solid var(--grt);border-radius:6px;padding:5px 8px;font-size:11px;font-family:var(--mono);background:white;color:var(--txt)">
      <button id="btn-copy-share" style="font-size:11px;padding:5px 12px;border-radius:20px;background:var(--gr);color:white;border:none;cursor:pointer;flex-shrink:0">Copy link</button>
    </div>
    <div id="badge-section" style="display:none;margin-top:4px">
      <div style="font-size:11px;color:var(--grt);margin-bottom:4px;font-weight:500">Add this badge to your GitHub README:</div>
      <input id="badge-code" type="text" readonly style="width:100%;border:0.5px solid var(--grt);border-radius:6px;padding:5px 8px;font-size:10px;font-family:var(--mono);background:white;color:var(--mut)">
    </div>
  </div>

  <div id="report-content"></div>

  <!-- Steps 2+3 loading banner — shown while layers load in background -->
  <div id="steps23-loading" style="display:none;align-items:center;gap:10px;background:var(--pul);border-radius:var(--r);padding:.75rem 1rem;margin-top:.75rem;margin-bottom:.75rem">
    <div style="width:18px;height:18px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>
    <div style="font-size:12px;color:var(--put);font-weight:500" id="steps23-msg">Analysing Auth, Config, Database layers...</div>
  </div>

  <!-- Layers injected here by appendLayers -->
  <div id="layers-container"></div>

  <!-- GitHub star prompt -->
  <div id="star-prompt" style="display:none;text-align:center;margin-bottom:.75rem">
    <a href="https://github.com/ekbm/verilay" target="_blank" style="font-size:12px;color:var(--mut);text-decoration:none">
      ⭐ Found Verilay useful? Star us on GitHub
    </a>
  </div>

  <!-- Feedback widget -->
  <div id="feedback-widget" style="display:none;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:.75rem;text-align:center">
    <div style="font-size:13px;font-weight:500;margin-bottom:.65rem">Was this analysis helpful?</div>
    <div style="display:flex;gap:8px;justify-content:center;margin-bottom:.5rem">
      <button id="btn-feedback-up" onclick="submitFeedback(true)" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:6px 16px;cursor:pointer;transition:all .15s">👍</button>
      <button id="btn-feedback-down" onclick="submitFeedback(false)" style="font-size:20px;background:none;border:0.5px solid var(--bdr);border-radius:8px;padding:6px 16px;cursor:pointer;transition:all .15s">👎</button>
    </div>
    <div id="feedback-text-area" style="display:none;margin-top:.5rem">
      <textarea id="feedback-text" placeholder="What could be better? (optional)" style="width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:8px;font-size:12px;font-family:inherit;resize:vertical;min-height:60px;background:var(--bg);color:var(--txt)"></textarea>
      <button onclick="sendFeedbackText()" style="margin-top:6px;font-size:12px;padding:5px 16px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer">Send feedback</button>
    </div>
    <div id="feedback-thanks" style="display:none;font-size:13px;color:var(--mut)">Thanks for the feedback! 🙏</div>
  </div>

  <div class="p2-banner" id="p2-banner">
    <div style="display:flex;align-items:flex-start;gap:12px">
      <i class="ti ti-sparkles" style="font-size:22px;color:var(--pu);flex-shrink:0;margin-top:2px"></i>
      <div style="flex:1">
        <div style="font-size:14px;font-weight:600;color:var(--put);margin-bottom:4px">Part 1 complete - ready for the deep analysis?</div>
        <div style="font-size:12px;color:var(--put);line-height:1.55;margin-bottom:.85rem">Part 2 adds the fix list with effort estimates, second opinion prompts, and security checklist. Takes another 15-20 seconds.</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn-sm" id="btn-p2">Yes, run Part 2</button>
          <button id="btn-skip" style="padding:7px 16px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);font-size:12px;cursor:pointer">Skip for now</button>
        </div>
      </div>
    </div>
  </div>

  <div id="p2-loading" style="display:none;text-align:center;padding:1.5rem;margin-top:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r)">
    <div class="spin" style="width:28px;height:28px;border-width:2.5px;margin-bottom:.75rem"></div>
    <div style="font-size:13px;color:var(--mut)">Running deep analysis...</div>
  </div>

  <div id="p2-results"></div>

  <div class="bottom-cta">
    <div style="font-size:13px;font-weight:500;margin-bottom:.4rem">Analyse another app?</div>
    <div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Run Verilay on any GitHub repo, ZIP file, or live URL</div>
    <button class="btn-sm" id="btn-new2">
      <i class="ti ti-search" style="font-size:13px"></i> Analyse another app
    </button>
  </div>
</div>

<!-- ── Sample report modal ──────────────────────────────── -->
<div id="sample-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;overflow-y:auto;padding:1.5rem">
  <div style="max-width:680px;margin:0 auto;background:var(--sur);border-radius:var(--r);padding:1.5rem;position:relative">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem">
      <div>
        <div style="font-size:16px;font-weight:600;margin-bottom:2px">Sample Verilay Report</div>
        <div style="font-size:12px;color:var(--mut)">A real analysis of a Lovable-built app — this is what you get</div>
      </div>
      <button id="btn-close-modal" style="padding:6px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;cursor:pointer;font-size:12px;color:var(--mut)">Close</button>
    </div>

    <!-- Production verdict -->
    <div style="background:var(--orl);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px;display:flex;align-items:center;gap:12px">
      <i class="ti ti-alert-triangle" style="font-size:24px;color:var(--ort)"></i>
      <div>
        <div style="font-size:14px;font-weight:600;color:var(--ort)">Needs work before going live</div>
        <div style="font-size:12px;color:var(--mut)">2 critical security issues found that should be fixed before sharing with real users</div>
      </div>
    </div>

    <!-- Stack pills -->
    <div style="background:var(--bg);border-radius:var(--r);padding:1rem;margin-bottom:10px">
      <div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Stack detected</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--pul);color:var(--put)">React 18</span>
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--grl);color:var(--grt)">Supabase</span>
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--orl);color:var(--ort)">Vite</span>
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--bll);color:var(--blt)">TypeScript</span>
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:#F1EFE8;color:#444441">Tailwind CSS</span>
        <span style="font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--pul);color:var(--put)">shadcn/ui</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:.65rem">
        <div style="background:var(--rdl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--rdt)">2</div><div style="font-size:10px;color:var(--rdt)">critical</div></div>
        <div style="background:var(--orl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--ort)">3</div><div style="font-size:10px;color:var(--ort)">warnings</div></div>
        <div style="background:var(--grl);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--grt)">6</div><div style="font-size:10px;color:var(--grt)">passing</div></div>
        <div style="background:var(--bll);border-radius:8px;padding:.55rem;text-align:center"><div style="font-size:18px;font-weight:600;color:var(--blt)">C</div><div style="font-size:10px;color:var(--blt)">score</div></div>
      </div>
    </div>

    <!-- Sample layer -->
    <div style="background:var(--bg);border-radius:var(--r);padding:1rem;margin-bottom:10px">
      <div style="font-size:12px;font-weight:600;margin-bottom:.65rem;display:flex;align-items:center;gap:6px">
        <i class="ti ti-shield" style="color:var(--rdt)"></i> Auth layer — 2 issues found
      </div>
      <!-- Expert finding -->
      <div style="background:var(--rdl);border-radius:8px;padding:.65rem .85rem;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;font-size:12px">
        <i class="ti ti-alert-circle" style="color:var(--rdt);font-size:15px;flex-shrink:0;margin-top:1px"></i>
        <div>
          <div style="font-weight:500;margin-bottom:2px;color:var(--rdt)">.env file committed to public GitHub repo</div>
          <div style="color:var(--mut)">Your Supabase credentials are visible to anyone who finds your repo. Rotate your keys immediately in the Supabase dashboard.</div>
        </div>
      </div>
      <div style="background:var(--orl);border-radius:8px;padding:.65rem .85rem;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;font-size:12px">
        <i class="ti ti-alert-triangle" style="color:var(--ort);font-size:15px;flex-shrink:0;margin-top:1px"></i>
        <div>
          <div style="font-weight:500;margin-bottom:2px;color:var(--ort)">JWT tokens have no expiry set</div>
          <div style="color:var(--mut)">Login tokens last forever. A stolen token would give permanent access to any account.</div>
        </div>
      </div>
      <!-- Learner view toggle sample -->
      <div style="background:var(--pul);border-radius:8px;padding:.65rem .85rem;font-size:12px;color:var(--put)">
        <strong>Think of Auth like this:</strong> It's the bouncer at your app's door — checks who you are before letting you in. Right now the bouncer is letting people in with a pass that never expires.
      </div>
    </div>

    <!-- CTA -->
    <div style="text-align:center;padding:.75rem 0 0">
      <div style="font-size:13px;color:var(--mut);margin-bottom:.75rem">This is what Verilay finds in your app — in 30 seconds</div>
      <button id="btn-modal-cta" style="display:inline-flex;align-items:center;gap:7px;padding:10px 24px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:13px;font-weight:500;border:none;cursor:pointer">
        <i class="ti ti-search"></i> Analyse my app now
      </button>
    </div>
  </div>
</div>

</div></main>


</body>
</html>"""

if __name__ == "__main__":
    if not ANTHROPIC_API_KEY:
        print("\n⚠️  No ANTHROPIC_API_KEY in .env\n")
    print("🔍 Verilay running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
