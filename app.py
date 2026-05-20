#!/usr/bin/env python3
"""
Verilay v2 — Codebase analyser for non-developers
New in v2:
  - Deep learning content per layer (concepts, analogies, quizzes)
  - Second opinion export — copy code + prompt to verify in any AI tool
  - Production readiness checklist
  - "Why this matters" for every finding
"""

import os, json, base64, zipfile, io, requests
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

PRIORITY_FILES = [
    "package.json","requirements.txt","pyproject.toml","Pipfile",
    "composer.json","go.mod","Gemfile",
    ".env",".env.example",".env.sample",
    "vite.config.ts","vite.config.js",
    "supabase/config.toml",
    "src/lib/supabase.ts","src/lib/supabase.js",
    "src/integrations/supabase/client.ts",
    "lib/db.ts","lib/database.ts","database.py",
    "prisma/schema.prisma",
    "src/auth.ts","auth.py","middleware/auth.ts",
    "app.py","main.py","index.js","server.js",
    "src/App.tsx","src/App.jsx","src/main.tsx",
    "src/router.tsx","src/routes.tsx",
    ".gitignore",
]
KEYWORDS = ["auth","login","signup","database","db","model",
            "route","api","middleware","config","schema"]
MAX_FILES, MAX_FILE_SIZE = 20, 15000

# ── Readers ──────────────────────────────────────────────────────────────────

def read_from_github(repo_url):
    clean = repo_url.replace("https://","").replace("http://","").strip("/")
    parts = clean.split("/")
    owner = parts[1] if parts[0]=="github.com" else parts[0]
    repo  = parts[2] if parts[0]=="github.com" else parts[1]
    base  = f"https://api.github.com/repos/{owner}/{repo}"
    hdrs  = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN: hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    tr = requests.get(f"{base}/git/trees/HEAD?recursive=1", headers=hdrs)
    if tr.status_code == 404: raise ValueError("Repo not found or private.")
    if tr.status_code == 403: raise ValueError("GitHub rate limit — add a GITHUB_TOKEN to .env")
    tr.raise_for_status()
    all_files = [i["path"] for i in tr.json().get("tree",[]) if i["type"]=="blob"]

    def fetch(p):
        try:
            r = requests.get(f"{base}/contents/{p}", headers=hdrs)
            if r.status_code != 200: return None
            d = r.json()
            if isinstance(d, list): return None  # directory listing not a file
            if not isinstance(d, dict): return None
            if d.get("encoding")=="base64":
                try: return base64.b64decode(d["content"]).decode("utf-8","replace")[:MAX_FILE_SIZE]
                except: return None
            return None
        except Exception: return None

    files = {}
    for p in PRIORITY_FILES:
        if p in all_files and len(files) < MAX_FILES:
            c = fetch(p)
            if c: files[p] = c
    for path in all_files:
        if len(files) >= MAX_FILES: break
        if path in files: continue
        fname = path.lower().split("/")[-1]
        for ext in [".ts",".js",".py",".json"]: fname = fname.replace(ext,"")
        if any(k in fname for k in KEYWORDS):
            c = fetch(path)
            if c: files[path] = c

    return files, f"{owner}/{repo}", all_files


def read_from_zip(zip_bytes, original_filename):
    project_name = original_filename.replace(".zip","")
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
            try: return zf.read(name_map[rel]).decode("utf-8","replace")[:MAX_FILE_SIZE]
            except: return None
        for p in PRIORITY_FILES:
            if p in name_map and len(files) < MAX_FILES:
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
    return files, project_name, list(name_map.keys())


def read_from_url(live_url):
    r = requests.get(live_url, timeout=10, headers={"User-Agent":"Verilay/1.0"})
    r.raise_for_status()
    domain = live_url.split("/")[2]
    project_name = domain.replace(".lovable.app","").replace(".replit.app","")
    files = {
        "index.html (live page)": r.text[:30000],
        "_meta.txt": f"LIVE URL SCAN: {live_url}\nSource code unavailable — surface analysis only."
    }
    return files, project_name, []

# ── Analyser ─────────────────────────────────────────────────────────────────

def call_claude(prompt, max_tokens=4000):
    """Single Claude API call with clean JSON parsing."""
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY in .env")
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
        json={"model":"claude-sonnet-4-5","max_tokens":max_tokens,"messages":[{"role":"user","content":prompt}]}
    )
    resp.raise_for_status()
    raw = resp.json()["content"][0]["text"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"): raw = raw[4:]
    if raw.endswith("```"): raw = raw.rsplit("```",1)[0]
    return json.loads(raw.strip())


def analyse(files, repo_name, input_method, all_file_list):
    """Part 1 — Stack, health, production verdict, layers. Fast, fits in 4000 tokens."""
    files_text = "".join(f"\n\n=== FILE: {p} ===\n{c}" for p, c in files.items())
    file_tree  = "\n".join(all_file_list[:60]) if all_file_list else "Not available"
    surface_note = "\nSURFACE SCAN only — analyse compiled HTML." if input_method=="url" else ""

    prompt = f"""You are Verilay, a codebase analysis tool for non-developers.
Input: {input_method} | Repo: {repo_name}{surface_note}

FILE TREE: {file_tree}
FILES: {files_text}

Return ONLY valid compact JSON — no markdown, no extra text:
{{"repo":"{repo_name}","input_method":"{input_method}","summary":"one sentence","built_with":"platform and why","analysis_depth":"full or surface","prod_ready":{{"verdict":"ready|needs_work|not_ready","confidence":"high|medium|low","reason":"one sentence"}},"stack":[{{"name":"","version":"","category":"frontend|backend|database|auth|styling|build|testing|other","plain_english":"one sentence"}}],"health":{{"critical":0,"warnings":0,"passing":0,"score":"A|B|C|D|F"}},"layers":[{{"name":"Auth|Database|API|Frontend|Libraries|Config|File Handling","status":"critical|warning|passing","expert":{{"summary":"2 sentences","findings":[{{"severity":"critical|warning|info|passing","title":"","detail":"","file":"","why_it_matters":""}}]}},"learner":{{"what_is_it":"2 sentences","analogy":"one sentence","what_it_does_in_your_app":"2 sentences","how_it_connects":"one sentence","key_concept":"one sentence","findings_plain":[{{"severity":"critical|warning|passing","plain_title":"","plain_detail":"","real_world_impact":"","action":""}}]}},"quiz":[{{"question":"","answer":"","why":""}}]}}]}}

Keep all text fields SHORT — 1-2 sentences max. Identify 4-6 layers only."""

    result = call_claude(prompt, max_tokens=4000)
    result["part2_loaded"] = False
    result["top_fixes"] = []
    result["second_opinion"] = {}
    result["security_score"] = {}
    return result


def analyse_part2(files, repo_name, findings_summary):
    """Part 2 — Fix list, second opinion prompts, security score. User triggered."""
    files_text = "".join(f"\n\n=== FILE: {p} ===\n{c}" for p, c in list(files.items())[:8])

    prompt = f"""You are Verilay continuing analysis of: {repo_name}
Key findings from part 1: {findings_summary}
Files sample: {files_text}

Return ONLY valid compact JSON:
{{"top_fixes":[{{"priority":1,"title":"","why_it_matters":"one sentence","how_to_fix":"2-3 steps","estimated_effort":"5 minutes|30 minutes|1 hour|1 day","code_to_copy":""}}],"second_opinion":{{"summary_prompt":"Complete self-contained prompt to paste into any AI to verify Verilay findings about {repo_name}","security_prompt":"Complete prompt to verify security findings","prod_checklist_prompt":"Complete prompt asking: is {repo_name} ready for production?"}},"security_score":{{"env_secrets_exposed":false,"auth_properly_configured":true,"rls_likely_configured":true,"dependencies_current":true,"no_hardcoded_secrets":true}}}}

Top fixes: 3-5 items. Keep text SHORT."""

    return call_claude(prompt, max_tokens=3000)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return render_template_string(HTML)

@app.route("/analyse", methods=["POST"])
def run_analysis():
    method = request.form.get("method","github")
    try:
        if method == "github":
            url = request.form.get("github_url","").strip()
            if not url: return jsonify({"error":"Please enter a GitHub URL"}), 400
            files, name, tree = read_from_github(url)
        elif method == "zip":
            f = request.files.get("zip_file")
            if not f: return jsonify({"error":"Please select a ZIP file"}), 400
            files, name, tree = read_from_zip(io.BytesIO(f.read()), f.filename)
        elif method == "url":
            url = request.form.get("live_url","").strip()
            if not url: return jsonify({"error":"Please enter a URL"}), 400
            files, name, tree = read_from_url(url)
        else:
            return jsonify({"error":"Unknown method"}), 400

        if not files: return jsonify({"error":"No readable files found. Try a different input method."}), 400
        result = analyse(files, name, method, tree)
        result["files_read"] = len(files)
        result["generated_at"] = datetime.now().strftime("%d %b %Y %H:%M")
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/analyse-part2", methods=["POST"])
def run_analysis_part2():
    """Part 2 triggered by user after reviewing Part 1."""
    try:
        data = request.get_json()
        repo_name = data.get("repo_name","")
        findings_summary = data.get("findings_summary","")
        files_cache = data.get("files_cache", {})
        result = analyse_part2(files_cache, repo_name, findings_summary)
        result["part2_loaded"] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verilay — Understand your AI-built app</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/dist/tabler-icons.min.css">
<style>
:root{--bg:#f8f8f7;--sur:#fff;--bdr:#e8e6e0;--txt:#1a1917;--mut:#6b6966;--r:10px;
--pu:#534AB7;--pul:#EEEDFE;--put:#3C3489;
--gr:#1D9E75;--grl:#E1F5EE;--grt:#085041;
--or:#EF9F27;--orl:#FAEEDA;--ort:#633806;
--rd:#E24B4A;--rdl:#FCEBEB;--rdt:#A32D2D;
--bll:#E6F1FB;--blt:#0C447C;
--mono:'SF Mono','Fira Code',monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--txt);min-height:100vh}
.wrap{max-width:780px;margin:0 auto;padding:2rem 1.25rem}
.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:.3rem}
.logo{font-size:22px;font-weight:600;color:var(--pu)}
.tagline{font-size:13px;color:var(--mut);margin-bottom:2rem}
/* method cards */
.mg{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:1.25rem}
.mc{border:1.5px solid var(--bdr);border-radius:var(--r);padding:.85rem .9rem;cursor:pointer;background:var(--sur);transition:all .15s;text-align:left}
.mc:hover{border-color:#aaa8ff}.mc.sel{border-color:var(--pu);background:var(--pul)}
.mc-icon{font-size:20px;margin-bottom:.4rem}.mc-title{font-size:13px;font-weight:500;margin-bottom:2px}
.mc-desc{font-size:11px;color:var(--mut);line-height:1.4}
.mbadge{font-size:10px;font-weight:500;padding:2px 7px;border-radius:20px;margin-top:5px;display:inline-block}
/* panels */
.ip{display:none;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:1rem}
.ip.vis{display:block}
label.lbl{font-size:12px;font-weight:500;margin-bottom:.4rem;display:block}
.sub{font-size:11px;color:var(--mut);margin-bottom:.6rem;line-height:1.45}
input[type=url],input[type=text]{width:100%;border:0.5px solid var(--bdr);border-radius:8px;padding:9px 12px;font-size:13px;font-family:var(--mono);background:var(--bg);color:var(--txt);outline:none;transition:border .15s}
input:focus{border-color:var(--pu)}
.fd{border:1.5px dashed var(--bdr);border-radius:8px;padding:1.5rem;text-align:center;cursor:pointer;position:relative;transition:all .15s;background:var(--bg)}
.fd:hover,.fd.dov{border-color:var(--pu);background:var(--pul)}
.fd input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.hint{background:var(--pul);border-radius:8px;padding:.65rem .85rem;font-size:12px;color:var(--put);margin-top:.65rem;line-height:1.5}
.hint ol{margin-top:.35rem;padding-left:1.1rem}.hint li{margin-bottom:2px}
.btn-main{width:100%;padding:12px;border-radius:var(--r);background:var(--pu);color:#fff;font-size:14px;font-weight:500;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:opacity .15s}
.btn-main:hover{opacity:.9}.btn-main:disabled{opacity:.5;cursor:not-allowed}
/* loading */
.ld{display:none;text-align:center;padding:2.5rem}
.ld.vis{display:block}
.spin{width:36px;height:36px;border:3px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;margin:0 auto 1rem}
@keyframes sp{to{transform:rotate(360deg)}}
.ld-msg{font-size:13px;color:var(--mut);margin-bottom:.35rem}
.ld-sub{font-size:11px;color:var(--mut)}
/* error */
.erbox{background:var(--rdl);border-radius:var(--r);padding:1rem;color:var(--rdt);font-size:13px;margin-bottom:1rem;display:none}
.erbox.vis{display:block}
/* report */
.rpt{display:none}.rpt.vis{display:block}
.btn-new{display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:6px 14px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer;margin-bottom:1rem}
.btn-new:hover{background:var(--sur)}
/* prod banner */
.prod-banner{border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.pb-icon{font-size:26px;flex-shrink:0}
.pb-verdict{font-size:15px;font-weight:600;margin-bottom:2px}
.pb-reason{font-size:12px;opacity:.85;line-height:1.4}
/* report header */
.rh{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1.1rem;margin-bottom:10px}
.rn{font-size:16px;font-weight:600;margin-bottom:3px}
.rs{font-size:12px;color:var(--mut);margin-bottom:.65rem}
.srow{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:.65rem}
.pill{font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px}
.hg{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:.65rem}
.hc{border-radius:8px;padding:.55rem;text-align:center}
.hn{font-size:18px;font-weight:600}.hl{font-size:10px;margin-top:1px}
/* tabs */
.tabs{display:flex;gap:5px;margin-bottom:1rem;flex-wrap:wrap}
.tab{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:500;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);transition:all .15s}
.tab.on{background:var(--pu);color:#fff;border-color:transparent}
.panel{display:none}.panel.on{display:block}
/* layer map */
.ll{display:grid;grid-template-columns:155px 1fr;gap:8px}
.lnav{display:flex;flex-direction:column;gap:5px}
.lb{display:flex;align-items:center;gap:8px;padding:7px 9px;border-radius:8px;cursor:pointer;border:0.5px solid transparent;background:var(--bg);width:100%;text-align:left;transition:all .15s}
.lb:hover,.lb.act{background:var(--sur);border-color:var(--bdr)}
.ldot{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-left:auto}
.lico{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.ca{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem;min-height:320px}
.mt{display:flex;gap:4px;margin-bottom:.85rem;flex-wrap:wrap}
.mb{font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;cursor:pointer;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);transition:all .15s}
.mb.on{background:var(--pu);color:#fff;border-color:transparent}
/* findings */
.fd2{border-radius:8px;padding:.65rem .85rem;margin-bottom:7px;display:flex;align-items:flex-start;gap:8px;font-size:12px;line-height:1.5}
/* learner cards */
.lc{background:var(--bg);border-radius:8px;padding:.75rem .9rem;margin-bottom:8px}
.lc-accent{border-left:2px solid var(--pu)}
.lc-title{font-size:12px;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:6px}
.lc-body{font-size:12px;color:var(--mut);line-height:1.55}
.analogy-box{background:var(--pul);border-radius:8px;padding:.65rem .85rem;margin-bottom:8px;font-size:12px;color:var(--put);line-height:1.5}
/* verify box */
.vbox{background:var(--bg);border:0.5px solid var(--bdr);border-radius:8px;padding:.65rem .85rem;margin-top:6px}
.vbox-label{font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:4px}
.vbox pre{font-size:11px;font-family:var(--mono);color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:120px;overflow-y:auto}
.btn-copy{font-size:11px;padding:4px 10px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer;margin-top:5px;display:inline-flex;align-items:center;gap:4px}
.btn-copy:hover{background:var(--sur)}.btn-copy.copied{color:var(--gr);border-color:var(--gr)}
/* quiz */
.quiz-card{background:var(--pul);border-radius:8px;padding:.75rem .9rem;margin-bottom:7px}
.qtext{font-size:12px;font-weight:500;margin-bottom:.5rem}
.qbtn{font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--put);background:transparent;color:var(--put);cursor:pointer;transition:all .15s}
.qbtn:hover{background:var(--pu);color:#fff;border-color:transparent}
.qans{display:none;margin-top:.5rem;font-size:12px;color:var(--put);line-height:1.45}
.qwhy{font-size:11px;opacity:.8;margin-top:3px}
/* stack grid */
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px}
.sc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.7rem .85rem}
.sch{display:flex;align-items:center;justify-content:space-between;margin-bottom:3px}
.scn{font-size:12px;font-weight:500;font-family:var(--mono)}
/* fixes */
.fc{background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px}
.fn{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)}
.ft{font-size:13px;font-weight:500;margin-bottom:3px}
.fw{font-size:12px;color:var(--mut);margin-bottom:4px;line-height:1.4}
.fh{font-size:11px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:5px}
.effort{font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px}
/* second opinion */
.so-card{background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);padding:1rem 1.1rem;margin-bottom:10px}
.so-title{font-size:13px;font-weight:500;margin-bottom:3px;display:flex;align-items:center;gap:7px}
.so-desc{font-size:12px;color:var(--mut);margin-bottom:.75rem;line-height:1.5}
.so-prompt{background:var(--bg);border-radius:8px;padding:.75rem .9rem;font-size:11px;font-family:var(--mono);color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;line-height:1.55}
.so-tools{display:flex;flex-wrap:wrap;gap:6px;margin-top:.65rem}
.tool-link{font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:4px;transition:all .15s}
.tool-link:hover{background:var(--pul);color:var(--put);border-color:var(--pu)}
/* security */
.si{border-radius:8px;padding:.6rem .85rem;margin-bottom:6px;display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500}
/* surface notice */
.sn{background:var(--orl);border-radius:var(--r);padding:.85rem 1rem;margin-bottom:10px;display:flex;align-items:flex-start;gap:8px;font-size:12px;color:var(--ort);line-height:1.5}
@media(max-width:540px){
  .mg{grid-template-columns:1fr}.ll{grid-template-columns:1fr}
  .lnav{flex-direction:row;flex-wrap:wrap}.lb{width:auto;flex:1;min-width:80px}
  .hg{grid-template-columns:repeat(2,1fr)}.mt{gap:3px}
}
</style>
</head>
<body>
<div class="wrap">

<div class="logo-row">
  <i class="ti ti-topology-star" style="font-size:24px;color:var(--pu)"></i>
  <span class="logo">Verilay</span>
  <span style="font-size:11px;color:var(--mut);margin-left:4px">v2</span>
</div>
<p class="tagline">Understand what your AI-built app is made of — learn while you validate, then verify with a second opinion.</p>

<!-- ── FORM ─────────────────────────────────────── -->
<div id="fs">
  <p style="font-size:13px;font-weight:500;margin-bottom:.65rem">How do you want to share your project?</p>
  <div class="mg">
    <div class="mc sel" data-method="github" id="mc-github">
      <div class="mc-icon"><i class="ti ti-brand-github"></i></div>
      <div class="mc-title">GitHub URL</div>
      <div class="mc-desc">Paste your repo link. Works for Lovable, Replit, any GitHub project.</div>
      <span class="mbadge" style="background:var(--grl);color:var(--grt)">Most complete</span>
    </div>
    <div class="mc" data-method="zip" id="mc-zip">
      <div class="mc-icon"><i class="ti ti-file-zip"></i></div>
      <div class="mc-title">Upload ZIP</div>
      <div class="mc-desc">Export from Lovable or Replit and upload here. No GitHub account needed.</div>
      <span class="mbadge" style="background:var(--pul);color:var(--put)">No GitHub needed</span>
    </div>
    <div class="mc" data-method="url" id="mc-url">
      <div class="mc-icon"><i class="ti ti-world"></i></div>
      <div class="mc-title">Live URL</div>
      <div class="mc-desc">Paste your published app link. Surface scan — libraries and services only.</div>
      <span class="mbadge" style="background:var(--orl);color:var(--ort)">Quick scan</span>
    </div>
  </div>

  <div class="ip vis" id="p-github">
    <label class="lbl">GitHub repository URL</label>
    <p class="sub">e.g. https://github.com/yourname/your-app</p>
    <input type="url" id="gh-url" placeholder="https://github.com/username/project">
    <div class="hint"><strong>Using Lovable?</strong> Your GitHub repo is auto-created.
      <ol><li>Open your project in Lovable</li><li>Click the GitHub icon top-right</li><li>Copy the URL and paste above</li></ol>
    </div>
  </div>

  <div class="ip" id="p-zip">
    <label class="lbl">Upload your project ZIP</label>
    <p class="sub"><strong>Lovable:</strong> Project menu (···) → Export project<br><strong>Replit:</strong> Three-dot menu → Download as ZIP</p>
    <div class="fd" id="dz">
      <input type="file" id="zf" accept=".zip" onchange="fileSel(this)">
      <div style="font-size:24px;color:var(--mut);margin-bottom:.4rem"><i class="ti ti-upload"></i></div>
      <div style="font-size:13px;color:var(--mut)">Drop ZIP here or click to browse</div>
      <div id="fn" style="font-size:12px;color:var(--gr);margin-top:.4rem;font-weight:500"></div>
    </div>
  </div>

  <div class="ip" id="p-url">
    <label class="lbl">Live app URL</label>
    <p class="sub">e.g. https://yourapp.lovable.app — surface scan only.</p>
    <input type="url" id="lu" placeholder="https://yourapp.lovable.app">
    <div class="hint" style="background:var(--orl);color:var(--ort)">
      <i class="ti ti-alert-triangle" style="margin-right:4px"></i>
      <strong>Surface scan.</strong> We detect libraries and services but not security config, DB structure, or auth patterns. Use GitHub or ZIP for a full analysis.
    </div>
  </div>

  <div class="erbox" id="eb"></div>
  <button class="btn-main" id="ab"><i class="ti ti-search"></i>Analyse my app</button>
</div>

<!-- ── LOADING ─────────────────────────────────── -->
<div class="ld" id="ld">
  <div class="spin"></div>
  <div class="ld-msg" id="lm">Reading your project files...</div>
  <div class="ld-sub" id="ls">This takes about 20–30 seconds</div>
</div>

<!-- ── REPORT ──────────────────────────────────── -->
<div class="rpt" id="rpt">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;padding:.65rem .9rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);position:sticky;top:0;z-index:10">
    <div style="display:flex;align-items:center;gap:8px">
      <i class="ti ti-topology-star" style="font-size:16px;color:var(--pu)"></i>
      <span style="font-size:13px;font-weight:500;color:var(--pu)">Verilay</span>
      <span style="font-size:11px;color:var(--mut)">Report ready</span>
    </div>
    <button id="btn-new-top" style="display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:20px;background:var(--pu);color:#fff;font-size:12px;font-weight:500;border:none;cursor:pointer">
      <i class="ti ti-plus" style="font-size:13px"></i> New analysis
    </button>
  </div>
  <div id="rc"></div>

  <!-- Part 2 prompt banner -->
  <div id="part2-banner" style="display:none;margin-top:1.25rem;background:var(--pul);border:1.5px solid var(--pu);border-radius:var(--r);padding:1.1rem 1.25rem">
    <div style="display:flex;align-items:flex-start;gap:12px">
      <i class="ti ti-sparkles" style="font-size:22px;color:var(--pu);flex-shrink:0;margin-top:2px"></i>
      <div style="flex:1">
        <div style="font-size:14px;font-weight:600;color:var(--put);margin-bottom:4px">Part 1 complete — ready for the deep analysis?</div>
        <div style="font-size:12px;color:var(--put);line-height:1.55;margin-bottom:.85rem">You've seen your stack, layers, and findings. Part 2 goes deeper — <strong>fix list with effort estimates</strong>, <strong>second opinion prompts</strong> to verify in Claude or ChatGPT, and your full <strong>security checklist</strong>. Takes another 15–20 seconds.</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button id="part2-btn" style="display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:20px;background:var(--pu);color:#fff;font-size:13px;font-weight:500;border:none;cursor:pointer">
            <i class="ti ti-chevron-right" style="font-size:13px"></i> Yes, run Part 2
          </button>
          <button id="btn-skip-p2" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:20px;border:0.5px solid var(--pu);background:transparent;color:var(--put);font-size:12px;cursor:pointer">
            Skip for now
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Part 2 loading -->
  <div id="part2-loading" style="display:none;text-align:center;padding:1.5rem;margin-top:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r)">
    <div style="width:28px;height:28px;border:2.5px solid var(--pul);border-top-color:var(--pu);border-radius:50%;animation:sp 1s linear infinite;margin:0 auto .75rem"></div>
    <div style="font-size:13px;color:var(--mut)" id="p2msg">Running deep analysis...</div>
  </div>

  <!-- Part 2 results injected here -->
  <div id="part2-results"></div>

  <div style="margin-top:1.5rem;padding:1rem;background:var(--sur);border:0.5px solid var(--bdr);border-radius:var(--r);text-align:center">
    <div style="font-size:13px;font-weight:500;margin-bottom:.4rem">Analyse another app?</div>
    <div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">Run Verilay on any GitHub repo, ZIP file, or live URL</div>
    <button id="btn-new-bottom" style="display:inline-flex;align-items:center;gap:6px;padding:9px 20px;border-radius:20px;background:var(--pu);color:#fff;font-size:13px;font-weight:500;border:none;cursor:pointer">
      <i class="ti ti-search" style="font-size:14px"></i> Analyse another app
    </button>
  </div>
</div>

</div><!-- /wrap -->

<script>
var method='github', layers={}, activeLayer=null, mode='expert';

function selMethod(m){
  method=m;
  document.querySelectorAll('.mc').forEach(c=>c.classList.remove('sel'));
  var mc = document.getElementById('mc-'+m);
  if(mc) mc.classList.add('sel');
  document.querySelectorAll('.ip').forEach(p=>p.classList.remove('vis'));
  var ip = document.getElementById('p-'+m);
  if(ip) ip.classList.add('vis');
}

// Wire up all buttons via event listeners (no inline onclick needed)
document.addEventListener('DOMContentLoaded', function(){
  // Method cards
  ['github','zip','url'].forEach(function(m){
    var el = document.getElementById('mc-'+m);
    if(el) el.addEventListener('click', function(){ selMethod(m); });
  });
  // Analyse button
  var ab = document.getElementById('ab');
  if(ab) ab.addEventListener('click', go);
  // Reset buttons
  var nb1 = document.getElementById('btn-new-top');
  if(nb1) nb1.addEventListener('click', reset);
  var nb2 = document.getElementById('btn-new-bottom');
  if(nb2) nb2.addEventListener('click', reset);
  // Part 2 buttons
  var p2btn = document.getElementById('part2-btn');
  if(p2btn) p2btn.addEventListener('click', loadPart2);
  var skipBtn = document.getElementById('btn-skip-p2');
  if(skipBtn) skipBtn.addEventListener('click', function(){
    document.getElementById('part2-banner').style.display='none';
  });
  // File input
  var zf = document.getElementById('zf');
  if(zf) zf.addEventListener('change', function(){ fileSel(this); });
  // Drag and drop on ZIP zone
  var dz = document.getElementById('dz');
  if(dz){
    dz.addEventListener('dragover', function(e){ e.preventDefault(); dz.classList.add('dov'); });
    dz.addEventListener('dragleave', function(){ dz.classList.remove('dov'); });
    dz.addEventListener('drop', function(e){
      e.preventDefault(); dz.classList.remove('dov');
      var f = e.dataTransfer.files[0];
      if(f){ document.getElementById('zf').files = e.dataTransfer.files; fileSel(document.getElementById('zf')); }
    });
  }
});

function fileSel(i){
  document.getElementById('fn').textContent = i.files[0]?'✓ '+i.files[0].name:'';
}

// drag/drop wired in DOMContentLoaded below

function showErr(m){var e=document.getElementById('eb');e.textContent=m;e.classList.add('vis');}
function hideErr(){document.getElementById('eb').classList.remove('vis');}

var msgs=[
  ['Reading your project files...','Fetching from GitHub API'],
  ['Identifying your tech stack...','Detecting frameworks and libraries'],
  ['Analysing each layer...','Auth, Database, API, Frontend...'],
  ['Running security checks...','Looking for exposed secrets and vulnerabilities'],
  ['Writing plain-English explanations...','Translating technical findings'],
  ['Building your second opinion prompts...','Almost done...'],
];
var mi=0,miv=null;
function startMsgs(){
  mi=0;
  document.getElementById('lm').textContent=msgs[0][0];
  document.getElementById('ls').textContent=msgs[0][1];
  miv=setInterval(()=>{
    mi=(mi+1)%msgs.length;
    document.getElementById('lm').textContent=msgs[mi][0];
    document.getElementById('ls').textContent=msgs[mi][1];
  },4000);
}
function stopMsgs(){if(miv)clearInterval(miv);}

async function go(){
  hideErr();
  var fd=new FormData();
  fd.append('method',method);
  if(method==='github'){
    var u=document.getElementById('gh-url').value.trim();
    if(!u){showErr('Please enter a GitHub URL');return;}
    fd.append('github_url',u);
  } else if(method==='zip'){
    var f=document.getElementById('zf').files[0];
    if(!f){showErr('Please select a ZIP file');return;}
    fd.append('zip_file',f);
  } else {
    var u=document.getElementById('lu').value.trim();
    if(!u){showErr('Please enter a URL');return;}
    fd.append('live_url',u);
  }
  document.getElementById('fs').style.display='none';
  document.getElementById('ld').classList.add('vis');
  document.getElementById('ab').disabled=true;
  startMsgs();
  try{
    var r=await fetch('/analyse',{method:'POST',body:fd});
    var d=await r.json();
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    if(d.error){document.getElementById('fs').style.display='block';showErr(d.error);return;}
    render(d);
  }catch(e){
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    document.getElementById('fs').style.display='block';
    showErr('Something went wrong. Please try again.');
  }
}

function reset(){
  document.getElementById('rpt').classList.remove('vis');
  document.getElementById('fs').style.display='block';
  document.getElementById('ab').disabled=false;
  layers={};activeLayer=null;mode='expert';
  currentReport=null; currentFilesCache={};
  document.getElementById('part2-banner').style.display='none';
  document.getElementById('part2-loading').style.display='none';
  document.getElementById('part2-results').innerHTML='';
}

/* ── render ──────────────────────────────────────────── */
function catColor(c){
  var m={frontend:'#EEEDFE:#3C3489',backend:'#E1F5EE:#085041',database:'#E1F5EE:#0F6E56',auth:'#FAECE7:#712B13',styling:'#F1EFE8:#444441',build:'#FAEEDA:#633806',testing:'#E6F1FB:#0C447C',other:'#F1EFE8:#5F5E5A'};
  return (m[c]||m.other).split(':');
}
function sevStyle(s){
  var m={critical:'background:var(--rdl);color:var(--rdt)',warning:'background:var(--orl);color:var(--ort)',passing:'background:var(--grl);color:var(--grt)',info:'background:var(--bll);color:var(--blt)'};
  return m[s]||m.info;
}
function sevIcon(s){
  return {critical:'ti-alert-circle',warning:'ti-alert-triangle',passing:'ti-circle-check',info:'ti-info-circle'}[s]||'ti-info-circle';
}
function effort(e){
  var m={'5 minutes':'#E1F5EE:#085041','30 minutes':'#EEEDFE:#3C3489','1 hour':'#FAEEDA:#633806','1 day':'#FCEBEB:#A32D2D'};
  var c=(m[e]||'#F1EFE8:#5F5E5A').split(':');
  return `<span class="effort" style="background:${c[0]};color:${c[1]}">${e||'varies'}</span>`;
}

function copyText(btn,text){
  navigator.clipboard.writeText(text).then(()=>{
    btn.textContent='✓ Copied!';btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},2000);
  });
}

function render(data){
  layers={};
  (data.layers||[]).forEach(l=>layers[l.name]=l);

  var isSurf=data.analysis_depth==='surface';
  var h=data.health||{};
  var pr=data.prod_ready||{};
  var so=data.second_opinion||{};

  /* prod banner */
  var pbMap={
    ready:['#EAF3DE','#27500A','ti-circle-check','✓ Production ready'],
    needs_work:['#FAEEDA','#633806','ti-alert-triangle','⚠ Needs work before going live'],
    not_ready:['#FCEBEB','#A32D2D','ti-alert-circle','✗ Not production ready']
  };
  var pb=pbMap[pr.verdict]||pbMap.needs_work;
  var conf=pr.confidence?` <span style="font-size:10px;opacity:.7">(${pr.confidence} confidence)</span>`:'';

  var html='';
  if(isSurf) html+=`<div class="sn"><i class="ti ti-alert-triangle" style="font-size:15px;flex-shrink:0;margin-top:1px"></i><div><strong>Surface scan only.</strong> We can see libraries and services but not security config or code structure. Use GitHub or ZIP for a full analysis.<br><br>${data.summary||''}</div></div>`;

  html+=`<div class="prod-banner" style="background:${pb[0]};color:${pb[1]}">
    <i class="ti ${pb[2]}" style="font-size:26px"></i>
    <div><div class="pb-verdict">${pb[3]}${conf}</div><div class="pb-reason">${pr.reason||''}</div></div>
  </div>`;

  /* header */
  var pills=(data.stack||[]).map(s=>{var c=catColor(s.category);return `<span class="pill" style="background:${c[0]};color:${c[1]}">${s.name||''} ${s.version||''}</span>`;}).join('');
  var hv=[h.critical||0,h.warnings||0,h.passing||0,h.score||'?'];
  var hl=['critical','warnings','passing','score'];
  var hcol=[['var(--rdl)','var(--rdt)'],['var(--orl)','var(--ort)'],['var(--grl)','var(--grt)'],['var(--bll)','var(--blt)']];
  var hcards=hv.map((v,i)=>`<div class="hc" style="background:${hcol[i][0]}"><div class="hn" style="color:${hcol[i][1]}">${v}</div><div class="hl" style="color:${hcol[i][1]}">${hl[i]}</div></div>`).join('');
  var mLabel={github:'GitHub repo',zip:'ZIP upload',url:'Live URL scan'}[data.input_method]||'';
  html+=`<div class="rh"><div class="rn">${data.repo||''}</div><div class="rs">${data.built_with||''} &nbsp;·&nbsp; ${mLabel} &nbsp;·&nbsp; ${data.files_read||0} files &nbsp;·&nbsp; ${data.generated_at||''}</div><div class="srow">${pills}</div><div class="hg">${hcards}</div></div>`;

  /* tabs */
  html+=`<div class="tabs">
    <button class="tab on" onclick="showTab('layers',this)">Layer map</button>
    <button class="tab" onclick="showTab('stack',this)">Full stack</button>
    <button class="tab" onclick="showTab('fixes',this)">Fix list</button>
    <button class="tab" onclick="showTab('opinion',this)">Second opinion</button>
    <button class="tab" onclick="showTab('security',this)">Security</button>
  </div>`;

  /* layer map */
  var icons={Auth:'ti-shield',Database:'ti-database',Config:'ti-lock',Frontend:'ti-layout',Libraries:'ti-package',API:'ti-api','File Handling':'ti-file',Storage:'ti-folder'};
  var sdot={critical:'#E24B4A',warning:'#EF9F27',passing:'#639922'};
  var sbg={critical:'var(--rdl)',warning:'var(--orl)',passing:'var(--grl)'};
  var sclr={critical:'var(--rdt)',warning:'var(--ort)',passing:'var(--grt)'};
  var lbtns=(data.layers||[]).map(l=>`<button class="lb" onclick="setLayer('${l.name}',this)"><div class="lico" style="background:${sbg[l.status]||sbg.passing};color:${sclr[l.status]||sclr.passing}"><i class="ti ${icons[l.name]||'ti-code'}"></i></div><span style="flex:1;font-size:12px;font-weight:500">${l.name}</span><div class="ldot" style="background:${sdot[l.status]||sdot.passing}"></div></button>`).join('');
  html+=`<div class="panel on" id="p-layers"><div class="ll"><div class="lnav">${lbtns}</div><div class="ca"><div class="mt"><button class="mb on" id="mb-e" onclick="setMode('expert')">Expert</button><button class="mb" id="mb-l" onclick="setMode('learner')">Learner</button><button class="mb" id="mb-q" onclick="setMode('quiz')">Quick quiz</button></div><div id="lc"></div></div></div></div>`;

  /* stack */
  var scards=(data.stack||[]).map(s=>{var c=catColor(s.category);return `<div class="sc"><div class="sch"><span class="scn">${s.name||''}</span><span class="pill" style="font-size:10px;background:${c[0]};color:${c[1]}">${s.category||''}</span></div><div style="font-size:11px;color:var(--mut);margin-bottom:2px">v${s.version||'?'}</div><div style="font-size:11px;color:var(--mut);line-height:1.4">${s.plain_english||''}</div></div>`;}).join('');
  html+=`<div class="panel" id="p-stack"><div class="sg">${scards}</div></div>`;

  /* fixes */
  var fcards=(data.top_fixes||[]).map(f=>{
    var cv=f.code_to_copy&&f.code_to_copy.trim()?`<div class="vbox" style="margin-top:6px"><div class="vbox-label">Code to verify</div><pre>${esc(f.code_to_copy)}</pre><button class="btn-copy" onclick="copyText(this,${JSON.stringify(f.code_to_copy||'')})"><i class="ti ti-copy" style="font-size:12px"></i>Copy</button></div>`:'';
    return `<div class="fc"><div style="display:flex;gap:12px;align-items:flex-start"><div class="fn">${f.priority||''}</div><div style="flex:1"><div class="ft">${f.title||''}</div><div class="fw">${f.why_it_matters||''}</div><div class="fh">${f.how_to_fix||''}</div>${effort(f.estimated_effort)}${cv}</div></div></div>`;
  }).join('');
  html+=`<div class="panel" id="p-fixes">${fcards}</div>`;

  /* second opinion */
  var soCards=[
    ['General second opinion','Get any AI to review the full analysis and confirm the findings.','ti-message-dots',so.summary_prompt||''],
    ['Security verification','Ask another AI to specifically verify the security findings.','ti-shield-check',so.security_prompt||''],
    ['Production readiness check','Ask another AI: is this app ready to go live?','ti-rocket',so.prod_checklist_prompt||''],
  ].map(([title,desc,icon,prompt])=>{
    if(!prompt) return '';
    var encoded=encodeURIComponent(prompt);
    return `<div class="so-card"><div class="so-title"><i class="ti ${icon}" style="font-size:15px;color:var(--pu)"></i>${title}</div><div class="so-desc">${desc}</div><div class="so-prompt">${esc(prompt)}</div><div class="so-tools"><button class="btn-copy" onclick="copyText(this,${JSON.stringify(prompt)})"><i class="ti ti-copy" style="font-size:12px"></i>Copy prompt</button><a class="tool-link" href="https://claude.ai" target="_blank"><i class="ti ti-external-link" style="font-size:11px"></i>Open Claude</a><a class="tool-link" href="https://chat.openai.com" target="_blank"><i class="ti ti-external-link" style="font-size:11px"></i>Open ChatGPT</a></div></div>`;
  }).join('');
  html+=`<div class="panel" id="p-opinion"><p style="font-size:12px;color:var(--mut);margin-bottom:.85rem;line-height:1.55">Copy any prompt below and paste it into Claude, ChatGPT, or share it with a developer for a second opinion. Verilay believes in transparency — always verify findings independently before shipping.</p>${soCards}</div>`;

  /* security */
  var checks=[['env_secrets_exposed','No secrets exposed in .env',true],['auth_properly_configured','Auth properly configured',false],['rls_likely_configured','Row Level Security configured',false],['dependencies_current','Dependencies are current',false],['no_hardcoded_secrets','No hardcoded secrets in code',false]];
  var sec=data.security_score||{};
  var sitems=checks.map(([k,label,inv])=>{
    var v=sec[k];var pass=(v===null||v===undefined)?null:(inv?!v:v);
    var bg,clr,ico;
    if(pass===true){bg='var(--grl)';clr='var(--grt)';ico='ti-circle-check';}
    else if(pass===false){bg='var(--rdl)';clr='var(--rdt)';ico='ti-alert-circle';}
    else{bg='#F1EFE8';clr='#5F5E5A';ico='ti-minus';}
    return `<div class="si" style="background:${bg};color:${clr}"><i class="ti ${ico}" style="font-size:15px"></i>${label}</div>`;
  }).join('');
  html+=`<div class="panel" id="p-security">${sitems}</div>`;

  document.getElementById('rc').innerHTML=html;
  document.getElementById('rpt').classList.add('vis');
  setTimeout(()=>{var f=document.querySelector('.lb');if(f)f.click();},50);

  // Store for part 2
  currentReport = data;

  // Show part 2 banner if not surface scan
  if(data.analysis_depth !== 'surface'){
    document.getElementById('part2-banner').style.display='block';
  }
}

function showTab(id,btn){
  ['layers','stack','fixes','opinion','security'].forEach(t=>{var e=document.getElementById('p-'+t);if(e)e.classList.remove('on');});
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('on'));
  var el=document.getElementById('p-'+id);if(el)el.classList.add('on');
  btn.classList.add('on');
}

function setLayer(name,btn){
  activeLayer=name;
  document.querySelectorAll('.lb').forEach(b=>b.classList.remove('act'));
  btn.classList.add('act');
  renderLayer();
}

function setMode(m){
  mode=m;
  ['e','l','q'].forEach(x=>document.getElementById('mb-'+x).classList.remove('on'));
  document.getElementById('mb-'+{expert:'e',learner:'l',quiz:'q'}[m]).classList.add('on');
  renderLayer();
}

function renderLayer(){
  if(!activeLayer||!layers[activeLayer])return;
  var layer=layers[activeLayer];
  var html='';

  if(mode==='expert'){
    var ex=layer.expert||{};
    html+=`<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem">${ex.summary||''}</div>`;
    (ex.findings||[]).forEach(f=>{
      var verifyHtml='';
      if(f.code_to_verify&&f.code_to_verify.trim()){
        verifyHtml=`<div class="vbox"><div class="vbox-label">Code snippet — copy to verify</div><pre>${esc(f.code_to_verify)}</pre><button class="btn-copy" onclick="copyText(this,${JSON.stringify(f.code_to_verify)})"><i class="ti ti-copy" style="font-size:12px"></i>Copy</button></div>`;
      }
      var whyHtml=f.why_it_matters?`<div style="font-size:11px;margin-top:4px;opacity:.85"><i class="ti ti-info-circle" style="font-size:11px;margin-right:3px"></i><strong>Why it matters:</strong> ${f.why_it_matters}</div>`:'';
      html+=`<div class="fd2" style="${sevStyle(f.severity)}"><i class="ti ${sevIcon(f.severity)}" style="font-size:15px;flex-shrink:0;margin-top:1px"></i><div style="flex:1"><div style="font-weight:500;margin-bottom:2px">${f.title||''}</div><div>${f.detail||''}${f.file?` <code style="font-size:10px;opacity:.7">${f.file}</code>`:''}</div>${whyHtml}${verifyHtml}</div></div>`;
    });

  } else if(mode==='learner'){
    var lrn=layer.learner||{};
    if(lrn.analogy) html+=`<div class="analogy-box"><i class="ti ti-bulb" style="margin-right:5px"></i><strong>Think of it like this:</strong> ${lrn.analogy}</div>`;
    html+=`<div class="lc lc-accent"><div class="lc-title"><i class="ti ti-info-circle" style="font-size:13px;color:var(--pu)"></i>What is ${layer.name}?</div><div class="lc-body">${lrn.what_is_it||''}</div></div>`;
    html+=`<div class="lc lc-accent"><div class="lc-title"><i class="ti ti-app-window" style="font-size:13px;color:var(--pu)"></i>In your app specifically</div><div class="lc-body">${lrn.what_it_does_in_your_app||''}</div></div>`;
    if(lrn.how_it_connects) html+=`<div class="lc lc-accent"><div class="lc-title"><i class="ti ti-arrows-transfer-up" style="font-size:13px;color:var(--pu)"></i>How it connects to other layers</div><div class="lc-body">${lrn.how_it_connects}</div></div>`;
    if(lrn.key_concept) html+=`<div class="lc" style="background:var(--pul);border-radius:8px"><div class="lc-title" style="color:var(--put)"><i class="ti ti-star" style="font-size:13px"></i>Key concept to remember</div><div class="lc-body" style="color:var(--put)">${lrn.key_concept}</div></div>`;
    if((lrn.findings_plain||[]).length){
      html+=`<div style="font-size:11px;font-weight:600;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin:.75rem 0 .4rem">What we found</div>`;
      lrn.findings_plain.forEach(f=>{
        var impact=f.real_world_impact?`<div style="font-size:11px;margin-top:4px;font-style:italic"><i class="ti ti-user" style="font-size:11px;margin-right:3px"></i>${f.real_world_impact}</div>`:'';
        var action=f.action?`<div style="margin-top:5px;font-size:11px;font-weight:500"><i class="ti ti-player-play" style="font-size:11px;margin-right:3px"></i>Action: ${f.action}</div>`:'';
        html+=`<div class="fd2" style="${sevStyle(f.severity)}"><i class="ti ${sevIcon(f.severity)}" style="font-size:15px;flex-shrink:0;margin-top:1px"></i><div style="flex:1"><div style="font-weight:500;margin-bottom:2px">${f.plain_title||''}</div><div>${f.plain_detail||''}</div>${impact}${action}</div></div>`;
      });
    }

  } else if(mode==='quiz'){
    var quiz=layer.quiz||[];
    if(!quiz.length){html='<div style="font-size:13px;color:var(--mut);padding:1rem 0">No quiz questions for this layer yet.</div>';}
    else{
      html+=`<div style="font-size:12px;color:var(--mut);margin-bottom:.85rem">Test your understanding of the ${layer.name} layer. Click to reveal each answer.</div>`;
      quiz.forEach((q,i)=>{
        html+=`<div class="quiz-card"><div class="qtext">${q.question||''}</div><button class="qbtn" onclick="revealQuiz(${i})">Reveal answer</button><div class="qans" id="qa-${i}"><strong>${q.answer||''}</strong><div class="qwhy">${q.why||''}</div></div></div>`;
      });
    }
  }

  document.getElementById('lc').innerHTML=html;
}

function revealQuiz(i){
  var el=document.getElementById('qa-'+i);
  if(el) el.style.display=el.style.display==='block'?'none':'block';
}

function esc(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Part 2 ────────────────────────────────────────────────────────────────────
var currentReport = null;
var currentFilesCache = {};

async function loadPart2(){
  var btn = document.getElementById('part2-btn');
  if(btn) btn.disabled = true;
  document.getElementById('part2-banner').style.display='none';
  document.getElementById('part2-loading').style.display='block';

  var msgs = ['Running deep analysis...','Building fix list...','Writing second opinion prompts...','Generating security checklist...'];
  var mi=0;
  var iv = setInterval(()=>{
    mi=(mi+1)%msgs.length;
    var el = document.getElementById('p2msg');
    if(el) el.textContent = msgs[mi];
  }, 3000);

  // Build a short findings summary from part1
  var summary = '';
  if(currentReport){
    var h = currentReport.health||{};
    summary = 'Health: '+h.critical+' critical, '+h.warnings+' warnings, score '+h.score+'. ';
    summary += 'Stack: '+(currentReport.stack||[]).slice(0,5).map(s=>s.name).join(', ')+'. ';
    summary += 'Layers: '+(currentReport.layers||[]).map(l=>l.name+' ('+l.status+')').join(', ');
  }

  try {
    var resp = await fetch('/analyse-part2', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        repo_name: currentReport ? currentReport.repo : '',
        findings_summary: summary,
        files_cache: currentFilesCache
      })
    });
    var data = await resp.json();
    clearInterval(iv);
    document.getElementById('part2-loading').style.display='none';
    if(data.error){
      document.getElementById('part2-results').innerHTML='<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">'+data.error+'</div>';
      return;
    }
    renderPart2(data);
  } catch(e) {
    clearInterval(iv);
    document.getElementById('part2-loading').style.display='none';
    document.getElementById('part2-results').innerHTML='<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">Part 2 failed. Please try again.</div>';
  }
}

function renderPart2(data){
  var html = '<div style="margin-top:1rem">';

  // Security checklist
  var sec = data.security_score||{};
  var checks=[['env_secrets_exposed','No secrets in .env committed',true],['auth_properly_configured','Auth properly configured',false],['rls_likely_configured','Row Level Security configured',false],['dependencies_current','Dependencies are current',false],['no_hardcoded_secrets','No hardcoded secrets in code',false]];
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin-bottom:.5rem">Security checklist</div>';
  checks.forEach(([k,label,inv])=>{
    var v=sec[k]; var pass=(v===null||v===undefined)?null:(inv?!v:v);
    var bg,clr,ico;
    if(pass===true){bg='var(--grl)';clr='var(--grt)';ico='ti-circle-check';}
    else if(pass===false){bg='var(--rdl)';clr='var(--rdt)';ico='ti-alert-circle';}
    else{bg='#F1EFE8';clr='#5F5E5A';ico='ti-minus';}
    html+=`<div style="border-radius:8px;padding:.55rem .85rem;margin-bottom:5px;display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500;background:${bg};color:${clr}"><i class="ti ${ico}" style="font-size:14px"></i>${label}</div>`;
  });

  // Fix list
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Fix list — most urgent first</div>';
  (data.top_fixes||[]).forEach(f=>{
    var effortColors={'5 minutes':'var(--grl):var(--grt)','30 minutes':'var(--pul):var(--put)','1 hour':'var(--orl):var(--ort)','1 day':'var(--rdl):var(--rdt)'};
    var ec=(effortColors[f.estimated_effort]||'#F1EFE8:#5F5E5A').split(':');
    var codeHtml = f.code_to_copy ? `<div style="margin-top:6px;background:var(--bg);border-radius:6px;padding:6px 8px;font-size:11px;font-family:var(--mono);color:var(--mut);white-space:pre-wrap;word-break:break-all">${esc(f.code_to_copy)}</div><button onclick="navigator.clipboard.writeText(${JSON.stringify(f.code_to_copy||'')})" style="font-size:10px;padding:3px 9px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer;margin-top:4px">Copy snippet</button>` : '';
    html+=`<div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start"><div style="width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)">${f.priority||''}</div><div style="flex:1"><div style="font-size:13px;font-weight:500;margin-bottom:3px">${esc(f.title||'')}</div><div style="font-size:12px;color:var(--mut);margin-bottom:4px;line-height:1.4">${esc(f.why_it_matters||'')}</div><div style="font-size:11px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:5px">${esc(f.how_to_fix||'')}</div><span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px;background:${ec[0]};color:${ec[1]}">${f.estimated_effort||'varies'}</span>${codeHtml}</div></div>`;
  });

  // Second opinion
  var so = data.second_opinion||{};
  var soItems = [['General second opinion',so.summary_prompt,'ti-message-dots'],['Security verification',so.security_prompt,'ti-shield-check'],['Production readiness',so.prod_checklist_prompt,'ti-rocket']];
  html += '<div style="font-size:10px;font-weight:600;color:var(--mut);letter-spacing:.05em;text-transform:uppercase;margin:.85rem 0 .5rem">Second opinion — verify with any AI</div>';
  html += '<div style="font-size:12px;color:var(--mut);margin-bottom:.75rem;line-height:1.5">Copy any prompt below into Claude, ChatGPT, or share with a developer to independently verify Verilay's findings.</div>';
  soItems.forEach(([title,prompt,icon])=>{
    if(!prompt) return;
    html+=`<div style="background:var(--sur);border:0.5px solid var(--bdr);border-radius:8px;padding:.85rem;margin-bottom:8px"><div style="font-size:12px;font-weight:500;margin-bottom:.4rem;display:flex;align-items:center;gap:6px"><i class="ti ${icon}" style="font-size:14px;color:var(--pu)"></i>${title}</div><div style="background:var(--bg);border-radius:6px;padding:.6rem .75rem;font-size:11px;font-family:var(--mono);color:var(--mut);white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto;line-height:1.5">${esc(prompt)}</div><div style="display:flex;gap:6px;margin-top:.5rem"><button onclick="navigator.clipboard.writeText(${JSON.stringify(prompt||'')})" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--mut);cursor:pointer">Copy prompt</button><a href="https://claude.ai" target="_blank" style="font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open Claude</a><a href="https://chat.openai.com" target="_blank" style="font-size:11px;font-weight:500;padding:4px 12px;border-radius:20px;border:0.5px solid var(--bdr);background:transparent;color:var(--txt);text-decoration:none">Open ChatGPT</a></div></div>`;
  });

  html += '</div>';
  document.getElementById('part2-results').innerHTML = html;
}
</script>
</body>
</html>"""

if __name__ == "__main__":
    if not ANTHROPIC_API_KEY:
        print("\n⚠️  No ANTHROPIC_API_KEY in .env — get one at console.anthropic.com\n")
    print("🔍 Verilay v2 running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
