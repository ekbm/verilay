#!/usr/bin/env python3
"""
Verilay v5 — Verification Layer for AI-built apps
Single-request streaming architecture — no inter-request cache dependency
"""

import os, json, base64, zipfile, io, requests, time, secrets as _secrets, uuid as _uuid, threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", _secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

# ── Report storage ─────────────────────────────────────────────────────────────
_reports = {}
REPORT_TTL = 86400

def save_report_data(data):
    report_id = _uuid.uuid4().hex[:12]
    _reports[report_id] = {"data": data, "saved_at": time.time()}
    expired = [k for k,v in _reports.items() if time.time()-v["saved_at"] > REPORT_TTL]
    for k in expired: del _reports[k]
    return report_id

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
        name_map = {strip(n): n for n in all_names}
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
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY set.")
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
        json={"model":"claude-sonnet-4-5","max_tokens":max_tokens,"messages":[{"role":"user","content":prompt}]},
        timeout=25
    )
    resp.raise_for_status()
    raw = resp.json()["content"][0]["text"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"): raw = raw[4:]
    if raw.endswith("```"): raw = raw.rsplit("```",1)[0]
    raw = raw.strip()
    try: return json.loads(raw)
    except json.JSONDecodeError:
        for i in range(len(raw)-1, 0, -1):
            if raw[i] == '}':
                try: return json.loads(raw[:i+1])
                except: continue
        raise ValueError("Could not parse Claude response. Please try again.")

def sanitise_for_prompt(content):
    """Truncate long lines to reduce prompt injection risk."""
    return "\n".join(l[:500] if len(l) > 500 else l for l in content.split("\n"))

def files_for(files, keys):
    out = ""
    total = 0
    for k in keys:
        if k in files and total < 20000:
            chunk = f"\n\n=== {k} ===\n{sanitise_for_prompt(files[k])}"
            out += chunk
            total += len(chunk)
    return out

# ── Analysis functions ─────────────────────────────────────────────────────────
def analyse_step1(files, tree, repo_name, method):
    tree_str = "\n".join(tree[:80]) if tree else "Not available"
    stack_keys = [k for k in files if any(sf in k for sf in ["package.json","requirements","Procfile","vite","tsconfig",".gitignore"])]
    ftext = files_for(files, stack_keys) or files_for(files, list(files.keys())[:3])
    is_surface = method == "url"

    prompt = (
        f"You are Verilay, a codebase analyser for non-developers.\n"
        f"Repo: {repo_name} | Input: {method}\n\n"
        f"FILE TREE:\n{tree_str}\n\nKEY FILES:\n{ftext}\n\n"
        "Return ONLY valid JSON:\n"
        '{"repo":"' + repo_name + '","input_method":"' + method + '",'
        '"analysis_depth":"' + ("surface" if is_surface else "full") + '",'
        '"summary":"one sentence what this app does",'
        '"built_with":"which AI platform built this and why",'
        '"prod_ready":{"verdict":"ready|needs_work|not_ready","confidence":"high|medium|low","reason":"one sentence"},'
        '"health":{"critical":0,"warnings":0,"passing":0,"score":"A|B|C|D|F"},'
        '"stack":[{"name":"","version":"","category":"frontend|backend|database|auth|styling|build|testing|other","plain_english":"one sentence"}]}'
        "\n\nBe accurate. Honest score — A means genuinely production-ready. Most AI apps score B or C."
    )
    return call_claude(prompt, max_tokens=1500)

def analyse_step2(files, repo_name):
    sec_keys = [k for k in files if any(w in k.lower() for w in
        ["auth","login",".env","config","secret","supabase","database","db","schema","prisma","password","token"])][:12]
    ftext = files_for(files, sec_keys) or files_for(files, list(files.keys())[:4])

    prompt = (
        f"You are Verilay analysing security layers of: {repo_name}\n\n"
        "Check specifically for: hardcoded secrets, exposed .env files, fallback secret keys that ship as defaults, "
        "SSRF via user-supplied URLs, prompt injection, missing auth, weak JWT config, Supabase RLS issues.\n\n"
        f"FILES:\n{ftext}\n\n"
        "Return ONLY valid JSON with exactly 3 layers. 1-2 sentences max per field. Max 3 findings per layer:\n"
        '{"layers":['
        '{"name":"Auth","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]},'
        '{"name":"Config","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]},'
        '{"name":"Database","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]}'
        ']}'
        "\n\nBe rigorous. Mark critical issues as critical. Do not give false passing scores."
    )
    return call_claude(prompt, max_tokens=2500)

def analyse_step3(files, repo_name):
    api_keys = [k for k in files if any(w in k.lower() for w in
        ["route","api","app.py","main.py","server","app.tsx","app.jsx","router","hook","component","package.json"])][:12]
    if "package.json" in files and "package.json" not in api_keys:
        api_keys.insert(0, "package.json")
    ftext = files_for(files, api_keys) or files_for(files, list(files.keys())[:4])

    prompt = (
        f"You are Verilay analysing API, Frontend and Libraries layers of: {repo_name}\n\n"
        f"FILES:\n{ftext}\n\n"
        "Return ONLY valid JSON with exactly 3 layers. 1-2 sentences max per field. Max 3 findings per layer:\n"
        '{"layers":['
        '{"name":"API","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]},'
        '{"name":"Frontend","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]},'
        '{"name":"Libraries","status":"critical|warning|passing",'
        '"expert":{"summary":"","findings":[{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}]},'
        '"learner":{"what_is_it":"","analogy":"","what_it_does_in_your_app":"","how_it_connects":"","key_concept":"","findings_plain":[{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}]},'
        '"quiz":[{"question":"","answer":"","why":""}]}'
        ']}'
    )
    return call_claude(prompt, max_tokens=2500)

def analyse_step4(repo_name, built_with, findings_summary):
    is_lovable = "lovable" in built_with.lower()
    is_replit  = "replit" in built_with.lower()
    platform   = "Lovable" if is_lovable else ("Replit" if is_replit else "your AI builder")

    prompt = (
        f"You are Verilay completing analysis of: {repo_name} (built with {built_with})\n\n"
        f"Findings summary:\n{findings_summary}\n\n"
        "Return ONLY valid JSON:\n"
        '{"top_fixes":['
        '{"priority":1,"title":"","why_it_matters":"1 sentence","how_to_fix":"2-3 steps",'
        '"estimated_effort":"5 minutes|30 minutes|1 hour|1 day",'
        f'"lovable_prompt":"Ready-to-paste prompt for {platform} AI chat to fix this. Start: In my {platform} app, [specific actionable fix]",'
        '"general_prompt":"Ready-to-paste prompt for any AI to fix this issue"}'
        '],'
        '"security_score":{"env_secrets_exposed":false,"auth_properly_configured":true,"rls_likely_configured":true,"dependencies_current":true,"no_hardcoded_secrets":true},'
        '"second_opinion":{'
        f'"summary_prompt":"Complete prompt to paste into any AI to verify Verilay findings about {repo_name}",'
        '"security_prompt":"Complete prompt to verify security findings",'
        f'"prod_checklist_prompt":"Complete prompt: is {repo_name} production ready? Include context."'
        '}}'
        "\n\n3-5 fixes by severity. Make lovable_prompt specific enough to produce an immediate fix."
    )
    return call_claude(prompt, max_tokens=2500)

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
                files, tree, repo_name = fetch_zip(io.BytesIO(f.read()), f.filename)
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
            yield json.dumps({"event":"step1","data":s1}) + "\n"

            # ── Step 2: Auth + Config + Database ───────────────────────
            yield json.dumps({"event":"status","data":"Analysing Auth, Config, Database layers..."}) + "\n"
            try:
                s2 = analyse_step2(files, repo_name)
                yield json.dumps({"event":"step2","data":s2}) + "\n"
            except Exception as e:
                yield json.dumps({"event":"step2_error","data":str(e)}) + "\n"
                s2 = {"layers":[]}

            # ── Step 3: API + Frontend + Libraries ─────────────────────
            yield json.dumps({"event":"status","data":"Analysing API, Frontend, Libraries layers..."}) + "\n"
            try:
                s3 = analyse_step3(files, repo_name)
                yield json.dumps({"event":"step3","data":s3}) + "\n"
            except Exception as e:
                yield json.dumps({"event":"step3_error","data":str(e)}) + "\n"
                s3 = {"layers":[]}

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

        # Update saved report with full data
        if report_id and report_id in _reports:
            _reports[report_id]["data"].update({
                "top_fixes":     result.get("top_fixes",[]),
                "security_score":result.get("security_score",{}),
                "second_opinion":result.get("second_opinion",{}),
            })

        result["part2_loaded"] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/save-report", methods=["POST"])
def save_report_route():
    try:
        data = request.get_json()
        report_id = save_report_data(data)
        return jsonify({"report_id": report_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/report/<report_id>")
def view_report(report_id):
    entry = _reports.get(report_id)
    if not entry:
        return "<h2 style='font-family:sans-serif;padding:2rem;color:#666'>Report not found or expired (reports kept 24 hours).</h2>", 404
    saved_json = json.dumps(entry["data"])
    extra = f"<script>window.addEventListener('load',function(){{try{{var d={saved_json};renderSavedReport(d);}}catch(e){{console.error(e);}}}});</script>"
    return render_template_string(HTML + extra)


@app.route("/export/markdown/<report_id>")
def export_markdown(report_id):
    entry = _reports.get(report_id)
    if not entry: return "Report not found", 404
    md = build_markdown(entry["data"])
    return Response(md, mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=verilay-{report_id}.md"})


@app.route("/badge/<path:repo>")
def badge(repo):
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
def index(): return render_template_string(HTML)

@app.route("/static/app.js")
def serve_js():
    from flask import Response
    return Response(APP_JS, mimetype="application/javascript")



APP_JS = """
var currentMethod = 'github';
var currentReport = null;
var currentFilesSample = '';
var currentLayers = {};
var activeLayer = null;
var activeMode = 'expert';

var savedReportId = null;

async function autoSaveReport(data) {
  // Silently save in background and show share URL when ready
  try {
    var reportData = Object.assign({}, data);
    var resp = await fetch('/save-report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(reportData)
    });
    var result = await resp.json();
    if (result.report_id) {
      savedReportId = result.report_id;
      var shareUrl = window.location.origin + '/report/' + result.report_id;
      // Update status label
      var statusEl = document.getElementById('report-status');
      if (statusEl) statusEl.textContent = 'Report saved';
      // Show share banner
      var shareInput = document.getElementById('share-url');
      var shareBanner = document.getElementById('share-banner');
      if (shareInput) shareInput.value = shareUrl;
      if (shareBanner) shareBanner.style.display = 'flex';
      // Show badge if we know the repo
      var repo = data.repo || '';
      if (repo && document.getElementById('badge-section')) {
        var badgeMd = '[![Verilay Score](https://verilay.dev/badge/' + repo + ')](https://verilay.dev/report/' + result.report_id + ')';
        document.getElementById('badge-code').value = badgeMd;
        document.getElementById('badge-section').style.display = 'block';
      }
    }
  } catch(e) {
    console.log('Auto-save failed silently:', e);
  }
}

async function saveReport() {
  var btn = document.getElementById('btn-save-report');
  if (!btn) return;
  btn.textContent = 'Saving...';
  btn.disabled = true;

  try {
    // Collect all current data
    var reportData = Object.assign({}, currentReport || {});
    reportData.layers = Object.values(currentLayers);
    if (window._step4Data) {
      reportData.top_fixes = window._step4Data.top_fixes || [];
      reportData.second_opinion = window._step4Data.second_opinion || {};
      reportData.security_score = window._step4Data.security_score || {};
    }

    var resp = await fetch('/save-report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(reportData)
    });
    var data = await resp.json();
    if (data.report_id) {
      savedReportId = data.report_id;
      var shareUrl = window.location.origin + '/report/' + data.report_id;
      document.getElementById('share-url').value = shareUrl;
      document.getElementById('share-banner').style.display = 'flex';
      btn.innerHTML = '<i class="ti ti-check" style="font-size:12px"></i> Saved';
      btn.style.color = 'var(--grt)';
    }
  } catch(e) {
    btn.textContent = 'Save failed';
    btn.disabled = false;
  }
}

function exportMarkdown() {
  if (!savedReportId) {
    // Save first then download
    saveReport().then(function() {
      setTimeout(function() {
        if (savedReportId) {
          window.location.href = '/export/markdown/' + savedReportId;
        }
      }, 1000);
    });
    return;
  }
  window.location.href = '/export/markdown/' + savedReportId;
}

function init() {
  // Method cards
  ['github','zip','url'].forEach(function(m) {
    var el = document.getElementById('mc-' + m);
    if (el) {
      el.addEventListener('click', function() {
        currentMethod = m;
        document.querySelectorAll('.mc').forEach(function(c) { c.classList.remove('sel'); });
        el.classList.add('sel');
        document.querySelectorAll('.ip').forEach(function(p) { p.classList.remove('vis'); });
        var panel = document.getElementById('p-' + m);
        if (panel) panel.classList.add('vis');
      });
    }
  });

  // Analyse button
  var btnAnalyse = document.getElementById('btn-analyse');
  if (btnAnalyse) btnAnalyse.addEventListener('click', runAnalysis);

  // New analysis buttons
  var btnNew = document.getElementById('btn-new');
  if (btnNew) btnNew.addEventListener('click', resetForm);
  var btnNew2 = document.getElementById('btn-new2');
  if (btnNew2) btnNew2.addEventListener('click', resetForm);

  // Save report / share link
  var btnSave = document.getElementById('btn-save-report');
  if (btnSave) btnSave.addEventListener('click', saveReport);

  // Copy share URL button
  var btnCopyShare = document.getElementById('btn-copy-share');
  if (btnCopyShare) btnCopyShare.addEventListener('click', function() {
    var url = document.getElementById('share-url').value;
    navigator.clipboard.writeText(url).then(function() {
      btnCopyShare.textContent = '✓ Copied!';
      setTimeout(function() { btnCopyShare.textContent = 'Copy link'; }, 2000);
    });
  });

  // Export markdown
  var btnMd = document.getElementById('btn-export-md');
  if (btnMd) btnMd.addEventListener('click', exportMarkdown);

  // Print / PDF
  var btnPrint = document.getElementById('btn-print');
  if (btnPrint) btnPrint.addEventListener('click', function() { window.print(); });

  // Part 2 buttons
  var btnP2 = document.getElementById('btn-p2');
  if (btnP2) btnP2.addEventListener('click', runPart2);
  var btnSkip = document.getElementById('btn-skip');
  if (btnSkip) btnSkip.addEventListener('click', function() {
    document.getElementById('p2-banner').style.display = 'none';
  });

  // File input
  var zf = document.getElementById('zf');
  if (zf) zf.addEventListener('change', function() {
    var name = this.files[0] ? this.files[0].name : '';
    document.getElementById('fn').textContent = name ? '✓ ' + name : '';
  });

  // Hero buttons — show form
  function showForm() {
    document.getElementById('hero-section').style.display = 'none';
    document.getElementById('form-section').style.display = 'block';
    window.scrollTo(0,0);
  }
  function showHero() {
    document.getElementById('hero-section').style.display = 'block';
    document.getElementById('form-section').style.display = 'none';
    window.scrollTo(0,0);
  }

  ['btn-start-hero','btn-hero-analyse','btn-hero-cta'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', showForm);
  });

  var backBtn = document.getElementById('btn-back-hero');
  if (backBtn) backBtn.addEventListener('click', showHero);

  // Sample modal
  var btnDemo = document.getElementById('btn-hero-demo');
  if (btnDemo) btnDemo.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'block';
    document.body.style.overflow = 'hidden';
  });
  var btnClose = document.getElementById('btn-close-modal');
  if (btnClose) btnClose.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'none';
    document.body.style.overflow = '';
  });
  var btnModalCta = document.getElementById('btn-modal-cta');
  if (btnModalCta) btnModalCta.addEventListener('click', function() {
    document.getElementById('sample-modal').style.display = 'none';
    document.body.style.overflow = '';
    showForm();
  });
  // Close modal on backdrop click
  var modal = document.getElementById('sample-modal');
  if (modal) modal.addEventListener('click', function(e) {
    if (e.target === modal) {
      modal.style.display = 'none';
      document.body.style.overflow = '';
    }
  });

  // Drag and drop
  var dz = document.getElementById('dz');
  if (dz) {
    dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.style.borderColor = 'var(--pu)'; });
    dz.addEventListener('dragleave', function() { dz.style.borderColor = ''; });
    dz.addEventListener('drop', function(e) {
      e.preventDefault(); dz.style.borderColor = '';
      var f = e.dataTransfer.files[0];
      if (f) {
        document.getElementById('zf').files = e.dataTransfer.files;
        document.getElementById('fn').textContent = '✓ ' + f.name;
      }
    });
  }
}

function showErr(msg) {
  var el = document.getElementById('eb');
  el.textContent = msg;
  el.classList.add('vis');
}
function hideErr() {
  document.getElementById('eb').classList.remove('vis');
}

var steps = [
  {msg: 'Reading your project files...', sub: 'Fetching from GitHub API', pct: 10},
  {msg: 'Detecting your tech stack...', sub: 'Identifying frameworks and libraries', pct: 25},
  {msg: 'Analysing each layer...', sub: 'Auth, Database, API, Frontend...', pct: 50},
  {msg: 'Running security checks...', sub: 'Looking for exposed secrets and issues', pct: 70},
  {msg: 'Writing plain-English explanations...', sub: 'Translating technical findings', pct: 90},
];
var stepIdx = 0, stepTimer = null, etaTimer = null, elapsedSecs = 0;

function setStep(i) {
  stepIdx = i;
  var s = steps[i] || steps[steps.length-1];
  document.getElementById('lm').textContent = s.msg;
  document.getElementById('ls').textContent = s.sub;

  // Update progress bar
  var bar = document.getElementById('prog-bar');
  var pct = document.getElementById('prog-pct');
  if (bar) bar.style.width = s.pct + '%';
  if (pct) pct.textContent = s.pct + '%';

  // Update step icons
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (!stepEl) continue;
    var icon = stepEl.querySelector('.step-icon');
    if (!icon) continue;
    if (j < i) {
      // Completed
      icon.style.background = 'var(--gr)';
      icon.style.borderColor = 'var(--gr)';
      icon.style.color = '#fff';
      icon.textContent = '✓';
      stepEl.querySelector('span').style.color = 'var(--grt)';
    } else if (j === i) {
      // Active
      icon.style.background = 'var(--pul)';
      icon.style.borderColor = 'var(--pu)';
      icon.style.color = 'var(--put)';
      icon.textContent = (j+1).toString();
      stepEl.querySelector('span').style.color = 'var(--put)';
      stepEl.querySelector('span').style.fontWeight = '500';
    } else {
      // Pending
      icon.style.background = '';
      icon.style.borderColor = 'var(--bdr)';
      icon.style.color = 'var(--mut)';
      icon.textContent = (j+1).toString();
      stepEl.querySelector('span').style.color = 'var(--mut)';
      stepEl.querySelector('span').style.fontWeight = '';
    }
  }
}

function updateEta() {
  elapsedSecs++;
  var remaining = Math.max(5, 35 - elapsedSecs);
  var eta = document.getElementById('prog-eta');
  if (eta) {
    if (remaining > 10) eta.textContent = '~' + remaining + ' seconds remaining';
    else if (remaining > 0) eta.textContent = 'Almost done...';
    else eta.textContent = 'Finalising...';
  }
}

function startMsgs() {
  stepIdx = 0;
  elapsedSecs = 0;
  setStep(0);

  // Reset all steps to pending
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (stepEl) {
      var icon = stepEl.querySelector('.step-icon');
      if (icon) {
        icon.style.background = '';
        icon.style.borderColor = 'var(--bdr)';
        icon.style.color = 'var(--mut)';
        icon.textContent = (j+1).toString();
      }
      var span = stepEl.querySelector('span');
      if (span) { span.style.color = 'var(--mut)'; span.style.fontWeight = ''; }
    }
  }

  // Advance steps on a timer
  var stepTimes = [0, 5000, 12000, 20000, 27000];
  stepTimes.forEach(function(t, i) {
    setTimeout(function() {
      if (stepIdx >= 0) setStep(i);
    }, t);
  });

  // ETA countdown
  etaTimer = setInterval(updateEta, 1000);
}

function stopMsgs() {
  stepIdx = -1;
  if (etaTimer) clearInterval(etaTimer);
  // Complete the bar
  var bar = document.getElementById('prog-bar');
  var pct = document.getElementById('prog-pct');
  var eta = document.getElementById('prog-eta');
  if (bar) bar.style.width = '100%';
  if (pct) pct.textContent = '100%';
  if (eta) eta.textContent = 'Complete!';
  // Mark all steps done
  for (var j = 0; j < steps.length; j++) {
    var stepEl = document.getElementById('step-' + j);
    if (!stepEl) continue;
    var icon = stepEl.querySelector('.step-icon');
    if (icon) {
      icon.style.background = 'var(--gr)';
      icon.style.borderColor = 'var(--gr)';
      icon.style.color = '#fff';
      icon.textContent = '✓';
    }
    var span = stepEl.querySelector('span');
    if (span) { span.style.color = 'var(--grt)'; }
  }
}

async function runAnalysis() {
  hideErr();
  var fd = new FormData();
  fd.append('method', currentMethod);
  if (currentMethod === 'github') {
    var url = document.getElementById('gh-url').value.trim();
    if (!url) { showErr('Please enter a GitHub URL'); return; }
    fd.append('github_url', url);
  } else if (currentMethod === 'zip') {
    var f = document.getElementById('zf').files[0];
    if (!f) { showErr('Please select a ZIP file'); return; }
    fd.append('zip_file', f);
  } else {
    var url = document.getElementById('lu').value.trim();
    if (!url) { showErr('Please enter a URL'); return; }
    fd.append('live_url', url);
  }
  document.getElementById('form-section').style.display = 'none';
  document.getElementById('ld').classList.add('vis');
  startMsgs();
  try {
    var resp = await fetch('/analyse-stream', { method: 'POST', body: fd });
    if (!resp.ok) { throw new Error('Server error ' + resp.status); }
    var reader = resp.body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';
    while (true) {
      var chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, {stream: true});
      var nlines = buffer.split('\n');
      buffer = nlines.pop();
      for (var i = 0; i < nlines.length; i++) {
        var line = nlines[i];
        line = line.trim();
        if (!line) continue;
        try { handleStreamEvent(JSON.parse(line)); }
        catch(e) { console.warn('Stream parse error:', line); }
      } // end for
    }
  } catch(e) {
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    document.getElementById('form-section').style.display = 'block';
    showErr(e.message || 'Something went wrong. Please try again.');
  }
}

function handleStreamEvent(evt) {
  switch(evt.event) {
    case 'status':
      document.getElementById('lm').textContent = evt.data;
      break;
    case 'step1':
      stopMsgs();
      document.getElementById('ld').classList.remove('vis');
      currentReport = evt.data;
      renderReport(evt.data);
      break;
    case 'step2':
    case 'step3':
      if (evt.data && evt.data.layers) appendLayers(evt.data.layers);
      break;
    case 'step2_error':
    case 'step3_error':
      showLayerError('Layer analysis error: ' + evt.data);
      break;
    case 'saved':
      savedReportId = evt.data.report_id;
      var shareUrl = window.location.origin + '/report/' + savedReportId;
      var shareInput = document.getElementById('share-url');
      var shareBanner = document.getElementById('share-banner');
      var statusEl = document.getElementById('report-status');
      if (shareInput) shareInput.value = shareUrl;
      if (shareBanner) shareBanner.style.display = 'flex';
      if (statusEl) statusEl.textContent = 'Report saved';
      var repo = currentReport ? currentReport.repo : '';
      if (repo && document.getElementById('badge-section')) {
        document.getElementById('badge-code').value =
          '[![Verilay Score](https://verilay.dev/badge/' + repo + ')](https://verilay.dev/report/' + savedReportId + ')';
        document.getElementById('badge-section').style.display = 'block';
      }
      break;
    case 'layers_complete':
      var lb = document.getElementById('steps23-loading');
      if (lb) lb.style.display = 'none';
      var p2 = document.getElementById('p2-banner');
      if (p2) p2.style.display = 'block';
      break;
    case 'error':
      stopMsgs();
      if (document.getElementById('ld').classList.contains('vis')) {
        document.getElementById('ld').classList.remove('vis');
        document.getElementById('form-section').style.display = 'block';
        showErr(evt.data);
      } else {
        showLayerError(evt.data);
      }
      break;
  }
}


function updateStepsLabel(msg) {
  var el = document.getElementById('steps23-msg');
  if (el) el.textContent = msg;
}

function resetForm() {
  document.getElementById('rpt').classList.remove('vis');
  document.getElementById('hero-section').style.display = 'block';
  document.getElementById('form-section').style.display = 'none';
  document.getElementById('p2-banner').style.display = 'none';
  document.getElementById('p2-loading').style.display = 'none';
  document.getElementById('p2-results').innerHTML = '';
  var s23 = document.getElementById('steps23-loading');
  if (s23) s23.style.display = 'none';
  var lc = document.getElementById('layers-container');
  if (lc) lc.innerHTML = '';
  currentReport = null;
  currentLayers = {};
  activeLayer = null;
  activeMode = 'expert';
  cacheKey = '';
  step1Data = {};
  window._step2Layers = [];
  window._step3Layers = [];
}

function catColors(cat) {
  var m = {frontend:'#EEEDFE:#3C3489',backend:'#E1F5EE:#085041',database:'#E1F5EE:#0F6E56',auth:'#FAECE7:#712B13',styling:'#F1EFE8:#444441',build:'#FAEEDA:#633806',testing:'#E6F1FB:#0C447C',other:'#F1EFE8:#5F5E5A'};
  return (m[cat] || m.other).split(':');
}
function sevStyle(s) {
  var m = {critical:'background:var(--rdl);color:var(--rdt)',warning:'background:var(--orl);color:var(--ort)',passing:'background:var(--grl);color:var(--grt)',info:'background:var(--bll);color:var(--blt)'};
  return m[s] || m.info;
}
function sevIcon(s) {
  return {critical:'ti-alert-circle',warning:'ti-alert-triangle',passing:'ti-circle-check',info:'ti-info-circle'}[s] || 'ti-info-circle';
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderReport(data) {
  currentReport = data;
  currentFilesSample = data.files_sample || '';
  currentLayers = {};
  (data.layers || []).forEach(function(l) { currentLayers[l.name] = l; });

  var isSurf = data.analysis_depth === 'surface';
  var h = data.health || {};
  var pr = data.prod_ready || {};

  var pbMap = {
    ready: ['#EAF3DE','#27500A','ti-circle-check','Production ready'],
    needs_work: ['#FAEEDA','#633806','ti-alert-triangle','Needs work before going live'],
    not_ready: ['#FCEBEB','#A32D2D','ti-alert-circle','Not production ready']
  };
  var pb = pbMap[pr.verdict] || pbMap.needs_work;

  var html = '';

  if (isSurf) {
    html += '<div style="background:var(--orl);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:10px;font-size:12px;color:var(--ort)"><strong>Surface scan only.</strong> Use GitHub or ZIP for a full analysis.</div>';
  }

  html += '<div class="prod-banner" style="background:' + pb[0] + ';color:' + pb[1] + '">';
  html += '<i class="ti ' + pb[2] + '" style="font-size:26px"></i>';
  html += '<div><div style="font-size:15px;font-weight:600;margin-bottom:2px">' + pb[3] + '</div>';
  html += '<div style="font-size:12px;opacity:.85">' + esc(pr.reason||'') + '</div></div></div>';

  // Scope notice — always shown, sets honest expectations
  html += '<div style="background:var(--bg);border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;margin-bottom:10px;display:flex;align-items:flex-start;gap:10px">';
  html += '<i class="ti ti-info-circle" style="font-size:16px;color:var(--mut);flex-shrink:0;margin-top:1px"></i>';
  html += '<div style="font-size:12px;color:var(--mut);line-height:1.55">';
  html += '<strong style="color:var(--txt)">What Verilay covers:</strong> This is a first-pass overview of your codebase — great for understanding what was built and catching obvious issues. ';
  html += 'For apps handling real users or sensitive data, we recommend a deeper review: ';
  html += '<a href="https://snyk.io" target="_blank" style="color:var(--pu);text-decoration:underline">Snyk</a> for dependency vulnerabilities, ';
  html += '<a href="https://coderabbit.ai" target="_blank" style="color:var(--pu);text-decoration:underline">CodeRabbit</a> for code review, ';
  html += 'or a developer security audit before going live with real user data.';
  html += '</div></div>';

  var pills = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<span class="pill" style="background:' + c[0] + ';color:' + c[1] + '">' + esc(s.name||'') + ' ' + esc(s.version||'') + '</span>';
  }).join('');

  var hvals = [h.critical||0, h.warnings||0, h.passing||0, h.score||'?'];
  var hlbls = ['critical','warnings','passing','score'];
  var hcols = [['var(--rdl)','var(--rdt)'],['var(--orl)','var(--ort)'],['var(--grl)','var(--grt)'],['var(--bll)','var(--blt)']];
  var hcards = hvals.map(function(v,i) {
    return '<div class="hc" style="background:' + hcols[i][0] + '"><div style="font-size:18px;font-weight:600;color:' + hcols[i][1] + '">' + v + '</div><div style="font-size:10px;color:' + hcols[i][1] + ';margin-top:1px">' + hlbls[i] + '</div></div>';
  }).join('');

  html += '<div class="rh">';
  html += '<div style="font-size:16px;font-weight:600;margin-bottom:3px">' + esc(data.repo||'') + '</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.65rem">' + esc(data.built_with||'') + ' &nbsp;·&nbsp; ' + (data.files_read||0) + ' files &nbsp;·&nbsp; ' + (data.generated_at||'') + '</div>';
  html += '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:.65rem">' + pills + '</div>';
  html += '<div class="hg">' + hcards + '</div></div>';

  html += '<div class="tabs" id="main-tabs">';
  html += '<button class="tab on" data-tab="layers">Layer map</button>';
  html += '<button class="tab" data-tab="stack">Full stack</button>';
  html += '</div>';

  var icons = {Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file'};
  var sdot = {critical:'#E24B4A',warning:'#EF9F27',passing:'#639922'};
  var sibg = {critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)'};
  var siclr = {critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)'};

  var lbtns = (data.layers||[]).map(function(l) {
    return '<button class="lb" data-layer="' + esc(l.name) + '">' +
      '<div class="lico" style="background:' + (sibg[l.status]||sibg.passing) + ';color:' + (siclr[l.status]||siclr.passing) + '"><i class="ti ' + (icons[l.name]||'ti-code') + '"></i></div>' +
      '<span style="flex:1">' + esc(l.name) + '</span>' +
      '<div class="ldot" style="background:' + (sdot[l.status]||sdot.passing) + '"></div>' +
      '</button>';
  }).join('');

  html += '<div class="panel on" id="p-layers">';
  html += '<div class="ll">';
  html += '<div class="lnav" id="layer-nav">';
  html += '<div id="layers-loading" style="font-size:11px;color:var(--mut);padding:.5rem .25rem;display:flex;align-items:center;gap:6px">';
  html += '<div style="width:14px;height:14px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
  html += 'Loading layers...</div>';
  html += lbtns;
  html += '</div>';
  html += '<div class="ca">';
  html += '<div id="mode-toggle" class="mt" style="display:none">';
  html += '<button class="mb on" data-mode="expert">Expert</button>';
  html += '<button class="mb" data-mode="learner">Learner</button>';
  html += '</div>';
  html += '<div id="layer-content" style="padding:.75rem 0">';
  html += '<div style="font-size:12px;color:var(--mut);display:flex;align-items:center;gap:8px">';
  html += '<div style="width:16px;height:16px;border:2px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;flex-shrink:0"></div>';
  html += 'Analysing your codebase — layers will appear shortly...</div>';
  html += '</div>';
  html += '</div></div></div>';

  var scards = (data.stack||[]).map(function(s) {
    var c = catColors(s.category);
    return '<div class="sc"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px"><span style="font-size:12px;font-weight:500">' + esc(s.name||'') + '</span><span class="pill" style="font-size:10px;background:' + c[0] + ';color:' + c[1] + '">' + esc(s.category||'') + '</span></div><div style="font-size:11px;color:var(--mut);margin-bottom:2px">v' + esc(s.version||'?') + '</div><div style="font-size:11px;color:var(--mut);line-height:1.4">' + esc(s.plain_english||'') + '</div></div>';
  }).join('');
  html += '<div class="panel" id="p-stack"><div class="sg">' + scards + '</div></div>';

  document.getElementById('report-content').innerHTML = html;
  document.getElementById('rpt').classList.add('vis');

  // Wire up tabs
  document.querySelectorAll('#main-tabs .tab').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#main-tabs .tab').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('on'); });
      var panel = document.getElementById('p-' + btn.dataset.tab);
      if (panel) panel.classList.add('on');
    });
  });

  // Wire up layer buttons
  document.querySelectorAll('#layer-nav .lb').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#layer-nav .lb').forEach(function(b) { b.classList.remove('act'); });
      btn.classList.add('act');
      activeLayer = btn.dataset.layer;
      renderLayer();
    });
  });

  // Wire up mode buttons
  document.querySelectorAll('#mode-toggle .mb').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#mode-toggle .mb').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      activeMode = btn.dataset.mode;
      renderLayer();
    });
  });

  // Auto-select first layer
  var firstLayer = document.querySelector('#layer-nav .lb');
  if (firstLayer) firstLayer.click();

  // Show Part 2 banner
  if (!isSurf) {
    document.getElementById('p2-banner').style.display = 'block';
  }
}

function renderLayer() {
  if (!activeLayer || !currentLayers[activeLayer]) return;
  var layer = currentLayers[activeLayer];
  var html = '';

  // Mode toggle button wiring (re-wire every time layer changes)
  document.querySelectorAll('#mode-toggle .mb').forEach(function(btn) {
    btn.onclick = function() {
      document.querySelectorAll('#mode-toggle .mb').forEach(function(b) { b.classList.remove('on'); });
      btn.classList.add('on');
      activeMode = btn.dataset.mode;
      renderLayer();
    };
  });

  if (activeMode === 'expert') {
    var ex = layer.expert || {};
    html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">' + esc(ex.summary||'') + '</div>';
    (ex.findings || []).forEach(function(f) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:15px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.title||'') + '</div>';
      html += '<div>' + esc(f.detail||'') + (f.file ? ' <code style="font-size:10px;opacity:.7">' + esc(f.file) + '</code>' : '') + '</div>';
      if (f.why_it_matters) html += '<div style="font-size:11px;margin-top:4px;opacity:.85"><strong>Why it matters:</strong> ' + esc(f.why_it_matters) + '</div>';
      html += '</div></div>';
    });
  } else if (activeMode === 'learner') {
    var lrn = layer.learner || {};
    if (lrn.analogy) html += '<div class="analogy"><i class="ti ti-bulb" style="margin-right:5px"></i><strong>Think of it like this:</strong> ' + esc(lrn.analogy) + '</div>';
    html += '<div class="lc"><div class="lc-title">What is ' + esc(layer.name) + '?</div><div class="lc-body">' + esc(lrn.what_is_it||'') + '</div></div>';
    html += '<div class="lc"><div class="lc-title">In your app specifically</div><div class="lc-body">' + esc(lrn.what_it_does_in_your_app||'') + '</div></div>';
    if (lrn.how_it_connects) html += '<div class="lc"><div class="lc-title">How it connects to other layers</div><div class="lc-body">' + esc(lrn.how_it_connects) + '</div></div>';
    if (lrn.key_concept) html += '<div style="background:var(--pul);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;font-size:12px;color:var(--put)"><strong>Key concept:</strong> ' + esc(lrn.key_concept) + '</div>';
    (lrn.findings_plain || []).forEach(function(f) {
      html += '<div class="finding" style="' + sevStyle(f.severity) + '">';
      html += '<i class="ti ' + sevIcon(f.severity) + '" style="font-size:15px;flex-shrink:0;margin-top:1px"></i>';
      html += '<div><div style="font-weight:500;margin-bottom:2px">' + esc(f.plain_title||'') + '</div>';
      html += '<div>' + esc(f.plain_detail||'') + '</div>';
      if (f.real_world_impact) html += '<div style="font-size:11px;margin-top:4px;font-style:italic">' + esc(f.real_world_impact) + '</div>';
      if (f.action) html += '<div style="margin-top:5px;font-size:11px;font-weight:500">Action: ' + esc(f.action) + '</div>';
      html += '</div></div>';
    });

    // Quiz as optional collapsible at bottom of learner mode
    var quiz = layer.quiz || [];
    if (quiz.length > 0) {
      html += '<div style="margin-top:.85rem;border-top:0.5px solid var(--bdr);padding-top:.75rem">';
      html += '<button id="quiz-toggle" style="font-size:12px;font-weight:500;padding:5px 14px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);cursor:pointer;display:flex;align-items:center;gap:5px">';
      html += '<i class="ti ti-brain" style="font-size:13px"></i> Test your understanding (optional quiz)';
      html += '</button>';
      html += '<div id="quiz-content" style="display:none;margin-top:.65rem">';
      quiz.forEach(function(q, i) {
        html += '<div class="qcard" style="margin-bottom:7px"><div style="font-size:12px;font-weight:500;margin-bottom:.5rem">' + esc(q.question||'') + '</div>';
        html += '<button id="qbtn-' + i + '" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--put);background:transparent;color:var(--put);cursor:pointer">Reveal answer</button>';
        html += '<div id="qans-' + i + '" style="display:none;margin-top:.5rem;font-size:12px;color:var(--put);line-height:1.45"><strong>' + esc(q.answer||'') + '</strong>';
        if (q.why) html += '<div style="font-size:11px;opacity:.8;margin-top:3px">' + esc(q.why) + '</div>';
        html += '</div></div>';
      });
      html += '</div></div>';
    }
  }

  document.getElementById('layer-content').innerHTML = html;

  // Wire quiz buttons
  var quiz = (currentLayers[activeLayer] && currentLayers[activeLayer].quiz) || [];
  quiz.forEach(function(q, i) {
    var btn = document.getElementById('qbtn-' + i);
    if (btn) btn.addEventListener('click', function() {
      var ans = document.getElementById('qans-' + i);
      if (ans) ans.style.display = ans.style.display === 'block' ? 'none' : 'block';
    });
  });

  // Wire quiz toggle
  var qt = document.getElementById('quiz-toggle');
  var qc = document.getElementById('quiz-content');
  if (qt && qc) {
    qt.addEventListener('click', function() {
      var open = qc.style.display === 'block';
      qc.style.display = open ? 'none' : 'block';
      qt.style.background = open ? 'transparent' : 'var(--pul)';
    });
  }
}

async function runPart2() {
  document.getElementById('p2-banner').style.display = 'none';
  document.getElementById('p2-loading').style.display = 'block';

  try {
    var h = currentReport ? (currentReport.health||{}) : {};
    var findings = 'Score: '+h.score+', Critical: '+h.critical+', Warnings: '+h.warnings+'. ';
    findings += 'Stack: '+(currentReport?(currentReport.stack||[]).slice(0,5).map(function(s){return s.name;}).join(', '):'') + '. ';
    findings += 'Layers: '+Object.keys(currentLayers).map(function(n){return n+'('+currentLayers[n].status+')';}).join(', ');
    var resp = await fetch('/analyse-step4', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        repo_name:  currentReport ? currentReport.repo : '',
        built_with: currentReport ? (currentReport.built_with||'') : '',
        findings_summary: findings,
        report_id: savedReportId || ''
      })
    });
    var data = await resp.json();
    document.getElementById('p2-loading').style.display = 'none';
    if (data.error) {
      document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">' + esc(data.error) + '</div>';
      return;
    }
    window._step4Data = data;
    renderPart2(data);
  } catch(e) {
    document.getElementById('p2-loading').style.display = 'none';
    document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">Deep analysis failed. Please try again.</div>';
  }
}

function showLayerError(msg) {
  var loadingEl = document.getElementById('layers-loading');
  if (loadingEl) {
    loadingEl.innerHTML = '<i class="ti ti-alert-triangle" style="font-size:13px;color:var(--ort);flex-shrink:0"></i><span style="font-size:11px;color:var(--ort)">' + msg + '</span>';
    loadingEl.style.display = 'flex';
  }
}

function appendLayers(newLayers) {
  var nav = document.getElementById('layer-nav');
  if (!nav) return;

  var icons = {Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file'};
  var sdot = {critical:'#E24B4A',warning:'#EF9F27',passing:'#639922'};
  var sibg = {critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)'};
  var siclr = {critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)'};

  // Hide the loading indicator once first layers arrive
  var loadingEl = document.getElementById('layers-loading');
  if (loadingEl) loadingEl.style.display = 'none';

  // Show mode toggle
  var mt = document.getElementById('mode-toggle');
  if (mt) mt.style.display = 'flex';

  newLayers.forEach(function(layer) {
    currentLayers[layer.name] = layer;

    var btn = document.createElement('button');
    btn.className = 'lb';
    btn.dataset.layer = layer.name;
    btn.innerHTML =
      '<div class="lico" style="background:' + (sibg[layer.status]||sibg.passing) + ';color:' + (siclr[layer.status]||siclr.passing) + '">' +
      '<i class="ti ' + (icons[layer.name]||'ti-code') + '"></i></div>' +
      '<span style="flex:1">' + esc(layer.name) + '</span>' +
      '<div class="ldot" style="background:' + (sdot[layer.status]||sdot.passing) + '"></div>';

    btn.addEventListener('click', function() {
      document.querySelectorAll('#layer-nav .lb').forEach(function(b) { b.classList.remove('act'); });
      btn.classList.add('act');
      activeLayer = layer.name;
      activeMode = document.querySelector('#mode-toggle .mb.on') ?
        document.querySelector('#mode-toggle .mb.on').dataset.mode : 'expert';
      renderLayer();
    });
    nav.appendChild(btn);
  });

  // Auto-select first layer button if none selected
  if (!activeLayer) {
    var firstBtn = document.querySelector('#layer-nav .lb');
    if (firstBtn) firstBtn.click();
  }
}

function renderPart2(data) {
  var html = '<div style="margin-top:1rem">';
  var sec = data.security_score || {};
  var checks = [
    ['env_secrets_exposed','No secrets exposed in .env file',true],
    ['auth_properly_configured','Auth properly configured',false],
    ['rls_likely_configured','Row Level Security configured',false],
    ['dependencies_current','Dependencies are current',false],
    ['no_hardcoded_secrets','No hardcoded secrets in code',false]
  ];
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Security checklist</div>';
  checks.forEach(function(c) {
    var v = sec[c[0]]; var inv = c[2];
    var pass = (v===null||v===undefined) ? null : (inv ? !v : v);
    var bg, clr, ico;
    if (pass===true) { bg='var(--grl)';clr='var(--grt)';ico='ti-circle-check'; }
    else if (pass===false) { bg='var(--rdl)';clr='var(--rdt)';ico='ti-alert-circle'; }
    else { bg='#F1EFE8';clr='#5F5E5A';ico='ti-minus'; }
    html += '<div class="si" style="background:' + bg + ';color:' + clr + '"><i class="ti ' + ico + '" style="font-size:15px"></i>' + c[1] + '</div>';
  });
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Fix list</div>';
  var builtWith = (currentReport && currentReport.built_with) ? currentReport.built_with.toLowerCase() : '';
  var isLovable = builtWith.includes('lovable');
  var isReplit  = builtWith.includes('replit');
  var isBolt    = builtWith.includes('bolt');
  var isV0      = builtWith.includes('v0');

  (data.top_fixes||[]).forEach(function(f, fi) {
    // Choose the right platform prompt
    var platformPrompt = f.general_prompt || f.lovable_prompt || '';
    var platformLabel = 'Copy AI prompt';
    var platformIcon = 'ti-copy';
    if (isLovable && f.lovable_prompt) {
      platformPrompt = f.lovable_prompt;
      platformLabel = 'Fix in Lovable';
      platformIcon = 'ti-wand';
    } else if (isReplit && f.replit_prompt) {
      platformPrompt = f.replit_prompt;
      platformLabel = 'Fix in Replit';
      platformIcon = 'ti-terminal';
    } else if (isBolt && f.general_prompt) {
      platformLabel = 'Fix in Bolt';
      platformIcon = 'ti-bolt';
    } else if (isV0 && f.general_prompt) {
      platformLabel = 'Fix in v0';
      platformIcon = 'ti-code';
    }

    html += '<div class="fc"><div style="display:flex;gap:12px;align-items:flex-start">';
    html += '<div style="width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)">' + (f.priority||'') + '</div>';
    html += '<div style="flex:1">';
    html += '<div style="font-size:13px;font-weight:500;margin-bottom:3px">' + esc(f.title||'') + '</div>';
    html += '<div style="font-size:12px;color:var(--mut);margin-bottom:4px;line-height:1.4">' + esc(f.why_it_matters||'') + '</div>';
    html += '<div style="font-size:11px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:.5rem">' + esc(f.how_to_fix||'') + '</div>';
    html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">';
    html += '<span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px;background:var(--pul);color:var(--put)">' + esc(f.estimated_effort||'varies') + '</span>';
    if (platformPrompt) {
      html += '<button id="fix-btn-' + fi + '" style="display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;background:var(--pu);color:#fff;border:none;cursor:pointer">';
      html += '<i class="ti ' + platformIcon + '" style="font-size:12px"></i> ' + platformLabel;
      html += '</button>';
      html += '<span id="fix-copied-' + fi + '" style="font-size:11px;color:var(--grt);display:none">✓ Copied! Paste into your AI chat</span>';
    }
    html += '</div>';
    if (platformPrompt) {
      html += '<div style="margin-top:.5rem;background:var(--bg);border-radius:6px;padding:.5rem .75rem;font-size:11px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:hidden;line-height:1.5" id="fix-prompt-' + fi + '">' + esc(platformPrompt) + '</div>';
    }
    html += '</div></div></div>';
  });

  // Wire fix buttons after render
  setTimeout(function() {
    (data.top_fixes||[]).forEach(function(f, fi) {
      var btn = document.getElementById('fix-btn-' + fi);
      var copied = document.getElementById('fix-copied-' + fi);
      var prompt = f.general_prompt || f.lovable_prompt || '';
      if (isLovable && f.lovable_prompt) prompt = f.lovable_prompt;
      else if (isReplit && f.replit_prompt) prompt = f.replit_prompt;
      if (btn && prompt) {
        btn.addEventListener('click', function() {
          navigator.clipboard.writeText(prompt).then(function() {
            btn.style.background = 'var(--gr)';
            if (copied) { copied.style.display = 'inline'; }
            setTimeout(function() {
              btn.style.background = 'var(--pu)';
              if (copied) { copied.style.display = 'none'; }
            }, 3000);
          });
        });
      }
    });
  }, 100);
  var so = data.second_opinion || {};
  var soItems = [
    ['General second opinion', so.summary_prompt, 'ti-message-dots'],
    ['Security verification', so.security_prompt, 'ti-shield-check'],
    ['Production readiness', so.prod_checklist_prompt, 'ti-rocket']
  ];
  // Next steps recommendation
  html += '<div style="background:var(--pul);border-radius:var(--r);padding:.85rem 1rem;margin:.85rem 0;border-left:3px solid var(--pu)">';
  html += '<div style="font-size:12px;font-weight:600;color:var(--put);margin-bottom:.4rem"><i class="ti ti-arrow-right" style="margin-right:4px"></i>Recommended next steps</div>';
  html += '<div style="font-size:12px;color:var(--put);line-height:1.6">';
  html += 'Verilay gives you a first-pass overview — good for understanding and catching obvious issues. For production apps we recommend going further:<br>';
  html += '• <a href="https://snyk.io" target="_blank" style="color:var(--pu)">Snyk</a> — free dependency and vulnerability scanning (connects to GitHub)<br>';
  html += '• <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu)">CodeRabbit</a> — AI code review on every pull request (free for open source)<br>';
  html += '• Share the second opinion prompts below with a developer for a human review<br>';
  html += '• Fix all critical issues before going live with real users or payments';
  html += '</div></div>';

  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Second opinion - verify with any AI</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Copy any prompt into Claude or ChatGPT to independently verify findings.</div>';
  soItems.forEach(function(item) {
    if (!item[1]) return;
    html += '<div class="so-card"><div style="font-size:12px;font-weight:500;margin-bottom:.4rem;display:flex;align-items:center;gap:6px"><i class="ti ' + item[2] + '" style="font-size:14px;color:var(--pu)"></i>' + item[0] + '</div>';
    html += '<div style="background:var(--bg);border-radius:6px;padding:.6rem .75rem;font-size:11px;font-family:monospace;color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto;line-height:1.5">' + esc(item[1]) + '</div>';
    html += '<div style="display:flex;gap:6px;margin-top:.5rem">';
    html += '<a href="https://claude.ai" target="_blank" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open Claude</a>';
    html += '<a href="https://chat.openai.com" target="_blank" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open ChatGPT</a>';
    html += '</div></div>';
  });
  html += '</div>';
  document.getElementById('p2-results').innerHTML = html;
}

// Start everything when DOM is ready
document.addEventListener('DOMContentLoaded', init);
"""

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verilay - Understand your AI-built app</title>
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--txt);min-height:100vh}
.wrap{max-width:1100px;margin:0 auto;padding:2rem 2.5rem}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:.3rem}
.logo-text{font-size:22px;font-weight:600;color:var(--pu)}
.tagline{font-size:13px;color:var(--mut);margin-bottom:2rem}
.label{font-size:13px;font-weight:500;margin-bottom:.65rem}
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
.mb{font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut)}
.mb.on{background:var(--pu);color:#fff;border-color:transparent}
.finding{border-radius:8px;padding:.65rem .85rem;margin-bottom:7px;display:flex;align-items:flex-start;gap:8px;font-size:12px;line-height:1.5}
.lc{background:var(--bg);border-left:2px solid var(--pu);border-radius:0 8px 8px 0;padding:.65rem .85rem;margin-bottom:7px}
.lc-title{font-size:12px;font-weight:500;margin-bottom:3px}
.lc-body{font-size:12px;color:var(--mut);line-height:1.5}
.analogy{background:var(--pul);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;font-size:12px;color:var(--put);line-height:1.5}
.qcard{background:var(--pul);border-radius:8px;padding:.75rem .9rem;margin-bottom:7px}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px}
.sc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.7rem .85rem}
.fc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.si{border-radius:8px;padding:.6rem .85rem;margin-bottom:6px;display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500}
.so-card{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.p2-banner{background:var(--pul);border:1.5px solid var(--pu);border-radius:var(--r);padding:1.1rem 1.25rem;margin-top:1.25rem;display:none}
.bottom-cta{margin-top:1.5rem;padding:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);text-align:center}
@media(max-width:540px){.mg{grid-template-columns:1fr}.ll{grid-template-columns:1fr}.hg{grid-template-columns:repeat(2,1fr)}}
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
      <strong style="color:var(--txt)">What Verilay is — and isn't.</strong>
      Verilay gives you a plain-English first-pass overview of your AI-built app. It highlights obvious issues, explains your tech stack, and helps you understand what was built.
      It is <em>not</em> a full penetration test or a replacement for a professional security audit.
      For apps going live with real user data or payments, we always recommend a deeper review from
      <a href="https://snyk.io" target="_blank" style="color:var(--pu);text-decoration:underline">Snyk</a>,
      <a href="https://coderabbit.ai" target="_blank" style="color:var(--pu);text-decoration:underline">CodeRabbit</a>,
      or a developer before launch. The second opinion prompts in every report make this easy.
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
  <div class="sticky-bar">
    <div style="display:flex;align-items:center;gap:8px">
      <i class="ti ti-topology-star" style="font-size:16px;color:var(--pu)"></i>
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

<script src="/static/app.js"></script>
</body>
</html>"""

if __name__ == "__main__":
    if not ANTHROPIC_API_KEY:
        print("\n⚠️  No ANTHROPIC_API_KEY in .env\n")
    print("🔍 Verilay running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
