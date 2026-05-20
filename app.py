#!/usr/bin/env python3
"""Verilay - Codebase analyser for non-developers"""

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
    "package.json","requirements.txt","pyproject.toml",
    ".env",".env.example",".env.sample",
    "vite.config.ts","vite.config.js",
    "supabase/config.toml",
    "src/lib/supabase.ts","src/lib/supabase.js",
    "src/integrations/supabase/client.ts",
    "lib/db.ts","lib/database.ts","database.py",
    "prisma/schema.prisma",
    "src/auth.ts","auth.py",
    "app.py","main.py","index.js","server.js",
    "src/App.tsx","src/App.jsx","src/main.tsx",
    ".gitignore",
]
KEYWORDS = ["auth","login","database","db","model","route","api","middleware","config","schema"]
MAX_FILES, MAX_FILE_SIZE = 20, 12000


def read_from_github(repo_url):
    clean = repo_url.replace("https://","").replace("http://","").strip("/")
    parts = clean.split("/")

    # Detect platform
    platform = parts[0] if parts else "github.com"

    if "gitlab.com" in platform:
        raise ValueError("GitLab support coming soon. Please use the ZIP upload method for now.")
    if "bitbucket.org" in platform:
        raise ValueError("Bitbucket support coming soon. Please use the ZIP upload method for now.")
    if "dev.azure.com" in platform or "azure.com" in platform:
        raise ValueError("Azure DevOps support coming soon. Please use the ZIP upload method for now.")

    owner = parts[1] if parts[0]=="github.com" else parts[0]
    repo  = parts[2] if parts[0]=="github.com" else parts[1]
    # Strip .git suffix if present
    repo = repo.replace(".git","")
    base  = "https://api.github.com/repos/" + owner + "/" + repo
    hdrs  = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        hdrs["Authorization"] = "Bearer " + GITHUB_TOKEN
    tr = requests.get(base + "/git/trees/HEAD?recursive=1", headers=hdrs)
    if tr.status_code == 404: raise ValueError("Repo not found or private.")
    if tr.status_code == 403: raise ValueError("GitHub rate limit hit.")
    tr.raise_for_status()
    all_files = [i["path"] for i in tr.json().get("tree",[]) if i["type"]=="blob"]
    def fetch(p):
        try:
            r = requests.get(base + "/contents/" + p, headers=hdrs)
            if r.status_code != 200: return None
            d = r.json()
            if isinstance(d, list): return None
            if d.get("encoding")=="base64":
                return base64.b64decode(d["content"]).decode("utf-8","replace")[:MAX_FILE_SIZE]
            return None
        except: return None
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
    return files, owner+"/"+repo, all_files


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
        "index.html (live page)": r.text[:25000],
        "_meta.txt": "LIVE URL SCAN: " + live_url + " - Surface analysis only."
    }
    return files, project_name, []


def call_claude(messages, max_tokens=4000):
    if not ANTHROPIC_API_KEY:
        raise ValueError("No ANTHROPIC_API_KEY set.")
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type":"application/json",
            "x-api-key":ANTHROPIC_API_KEY,
            "anthropic-version":"2023-06-01"
        },
        json={"model":"claude-sonnet-4-5","max_tokens":max_tokens,"messages":messages}
    )
    resp.raise_for_status()
    raw = resp.json()["content"][0]["text"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"): raw = raw[4:]
    if raw.endswith("```"): raw = raw.rsplit("```",1)[0]
    return json.loads(raw.strip())


def analyse_part1(files, repo_name, input_method):
    files_text = ""
    for p, c in files.items():
        files_text += "\n\n=== FILE: " + p + " ===\n" + c

    surface = "SURFACE SCAN - compiled HTML only." if input_method=="url" else ""

    prompt = (
        "You are Verilay, a codebase analyser for non-developers. "
        "Input: " + input_method + " | Repo: " + repo_name + " " + surface + "\n\n"
        "Files:\n" + files_text + "\n\n"
        "Return ONLY valid JSON, no markdown:\n"
        "{\"repo\":\"" + repo_name + "\","
        "\"input_method\":\"" + input_method + "\","
        "\"summary\":\"one sentence what this app does\"," 
        "\"built_with\":\"which AI platform and why\"," 
        "\"analysis_depth\":\"full or surface\"," 
        "\"prod_ready\":{\"verdict\":\"ready|needs_work|not_ready\",\"confidence\":\"high|medium|low\",\"reason\":\"one sentence\"}," 
        "\"stack\":[{\"name\":\"\",\"version\":\"\",\"category\":\"frontend|backend|database|auth|styling|build|testing|other\",\"plain_english\":\"one sentence\"}]," 
        "\"health\":{\"critical\":0,\"warnings\":0,\"passing\":0,\"score\":\"A|B|C|D|F\"}," 
        "\"layers\":[{\"name\":\"Auth|Database|API|Frontend|Libraries|Config|File Handling\",\"status\":\"critical|warning|passing\"," 
        "\"expert\":{\"summary\":\"2 sentences\",\"findings\":[{\"severity\":\"critical|warning|info|passing\",\"title\":\"\",\"detail\":\"\",\"file\":\"\",\"why_it_matters\":\"\"}]}," 
        "\"learner\":{\"what_is_it\":\"2 sentences\",\"analogy\":\"one sentence\",\"what_it_does_in_your_app\":\"2 sentences\",\"how_it_connects\":\"one sentence\",\"key_concept\":\"one sentence\",\"findings_plain\":[{\"severity\":\"critical|warning|passing\",\"plain_title\":\"\",\"plain_detail\":\"\",\"real_world_impact\":\"\",\"action\":\"\"}]}," 
        "\"quiz\":[{\"question\":\"\",\"answer\":\"\",\"why\":\"\"}]}]}"
        "\n\nKeep all text SHORT. Identify 4-6 layers only. Be accurate."
    )

    result = call_claude([{"role":"user","content":prompt}], max_tokens=4000)
    result["part2_loaded"] = False
    result["top_fixes"] = []
    result["second_opinion"] = {}
    result["security_score"] = {}
    return result


def analyse_part2(repo_name, findings_summary, files_sample):
    prompt = (
        "You are Verilay continuing analysis of: " + repo_name + "\n"
        "Part 1 findings: " + findings_summary + "\n"
        "Files sample: " + files_sample + "\n\n"
        "Return ONLY valid JSON, no markdown:\n"
        "{\"top_fixes\":[{\"priority\":1,\"title\":\"\",\"why_it_matters\":\"one sentence\",\"how_to_fix\":\"2-3 steps\",\"estimated_effort\":\"5 minutes|30 minutes|1 hour|1 day\",\"code_to_copy\":\"\"}],"
        "\"second_opinion\":{\"summary_prompt\":\"complete self-contained prompt for any AI to verify findings\",\"security_prompt\":\"complete prompt to verify security findings\",\"prod_checklist_prompt\":\"complete prompt asking if app is production ready\"},"
        "\"security_score\":{\"env_secrets_exposed\":false,\"auth_properly_configured\":true,\"rls_likely_configured\":true,\"dependencies_current\":true,\"no_hardcoded_secrets\":true}}"
        "\n\n3-5 fixes max. Keep text short."
    )
    return call_claude([{"role":"user","content":prompt}], max_tokens=3000)


@app.route("/")
def index():
    return render_template_string(HTML)


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
        if not files: return jsonify({"error":"No readable files found."}), 400
        result = analyse_part1(files, name, method)
        result["files_read"] = len(files)
        result["generated_at"] = datetime.now().strftime("%d %b %Y %H:%M")
        # Store small files sample for part2
        result["files_sample"] = "".join(
            p + ": " + c[:200] + "..." for p,c in list(files.items())[:5]
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/analyse-part2", methods=["POST"])
def run_part2():
    try:
        data = request.get_json()
        result = analyse_part2(
            data.get("repo_name",""),
            data.get("findings_summary",""),
            data.get("files_sample","")
        )
        result["part2_loaded"] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
.wrap{max-width:780px;margin:0 auto;padding:2rem 1.25rem}
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
.ll{display:grid;grid-template-columns:155px 1fr;gap:8px}
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
</style>
</head>
<body>
<div class="wrap">

<div class="logo">
  <i class="ti ti-topology-star" style="font-size:24px;color:var(--pu)"></i>
  <span class="logo-text">Verilay</span>
  <span style="font-size:11px;color:var(--mut);font-weight:400;margin-left:2px">verification layer</span>
</div>
<p class="tagline">Verilay reads your AI-built app and explains every layer in plain English — verify what was built, learn how it works, get a second opinion before you ship.</p>

<div id="form-section">
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
  <div class="spin"></div>
  <div class="ld-msg" id="lm">Reading your project files...</div>
  <div style="font-size:11px;color:var(--mut);margin-top:.35rem" id="ls">This takes about 20-30 seconds</div>
</div>

<div class="rpt" id="rpt">
  <div class="sticky-bar">
    <div style="display:flex;align-items:center;gap:8px">
      <i class="ti ti-topology-star" style="font-size:16px;color:var(--pu)"></i>
      <span style="font-size:13px;font-weight:500;color:var(--pu)">Verilay</span>
      <span style="font-size:11px;color:var(--mut)">Report ready</span>
    </div>
    <button class="btn-sm" id="btn-new">
      <i class="ti ti-plus" style="font-size:13px"></i> New analysis
    </button>
  </div>

  <div id="report-content"></div>

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

</div>

<script>
var currentMethod = 'github';
var currentReport = null;
var currentFilesSample = '';
var currentLayers = {};
var activeLayer = null;
var activeMode = 'expert';

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

var loadMsgs = [
  ['Reading your project files...', 'Fetching from GitHub API'],
  ['Identifying your tech stack...', 'Detecting frameworks and libraries'],
  ['Analysing each layer...', 'Auth, Database, API, Frontend...'],
  ['Running security checks...', 'Looking for exposed secrets'],
  ['Writing plain-English explanations...', 'Translating technical findings'],
];
var msgIdx = 0, msgTimer = null;

function startMsgs() {
  msgIdx = 0;
  document.getElementById('lm').textContent = loadMsgs[0][0];
  document.getElementById('ls').textContent = loadMsgs[0][1];
  msgTimer = setInterval(function() {
    msgIdx = (msgIdx + 1) % loadMsgs.length;
    document.getElementById('lm').textContent = loadMsgs[msgIdx][0];
    document.getElementById('ls').textContent = loadMsgs[msgIdx][1];
  }, 4000);
}
function stopMsgs() { if (msgTimer) clearInterval(msgTimer); }

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
    var resp = await fetch('/analyse', { method: 'POST', body: fd });
    var data = await resp.json();
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    if (data.error) {
      document.getElementById('form-section').style.display = 'block';
      showErr(data.error);
      return;
    }
    renderReport(data);
  } catch(e) {
    stopMsgs();
    document.getElementById('ld').classList.remove('vis');
    document.getElementById('form-section').style.display = 'block';
    showErr('Something went wrong. Please try again.');
  }
}

function resetForm() {
  document.getElementById('rpt').classList.remove('vis');
  document.getElementById('form-section').style.display = 'block';
  document.getElementById('p2-banner').style.display = 'none';
  document.getElementById('p2-loading').style.display = 'none';
  document.getElementById('p2-results').innerHTML = '';
  currentReport = null;
  currentLayers = {};
  activeLayer = null;
  activeMode = 'expert';
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
  html += '<div class="ll"><div class="lnav" id="layer-nav">' + lbtns + '</div>';
  html += '<div class="ca"><div class="mt" id="mode-toggle">';
  html += '<button class="mb on" data-mode="expert">Expert</button>';
  html += '<button class="mb" data-mode="learner">Learner</button>';
  html += '<button class="mb" data-mode="quiz">Quiz</button>';
  html += '</div><div id="layer-content"></div></div></div></div>';

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
  } else {
    var quiz = layer.quiz || [];
    if (!quiz.length) {
      html = '<div style="font-size:13px;color:var(--mut);padding:1rem 0">No quiz questions for this layer.</div>';
    } else {
      quiz.forEach(function(q, i) {
        html += '<div class="qcard"><div style="font-size:12px;font-weight:500;margin-bottom:.5rem">' + esc(q.question||'') + '</div>';
        html += '<button id="qbtn-' + i + '" style="font-size:11px;padding:4px 12px;border-radius:20px;border:0.5px solid var(--put);background:transparent;color:var(--put);cursor:pointer">Reveal answer</button>';
        html += '<div id="qans-' + i + '" style="display:none;margin-top:.5rem;font-size:12px;color:var(--put)"><strong>' + esc(q.answer||'') + '</strong>';
        if (q.why) html += '<div style="font-size:11px;opacity:.8;margin-top:3px">' + esc(q.why) + '</div>';
        html += '</div></div>';
      });
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
}

async function runPart2() {
  document.getElementById('p2-banner').style.display = 'none';
  document.getElementById('p2-loading').style.display = 'block';

  var summary = '';
  if (currentReport) {
    var h = currentReport.health || {};
    summary = 'Score: ' + h.score + ', Critical: ' + h.critical + ', Warnings: ' + h.warnings + '. ';
    summary += 'Stack: ' + (currentReport.stack||[]).slice(0,5).map(function(s){return s.name;}).join(', ') + '. ';
    summary += 'Layers: ' + (currentReport.layers||[]).map(function(l){return l.name+'('+l.status+')';}).join(', ');
  }

  try {
    var resp = await fetch('/analyse-part2', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        repo_name: currentReport ? currentReport.repo : '',
        findings_summary: summary,
        files_sample: currentFilesSample
      })
    });
    var data = await resp.json();
    document.getElementById('p2-loading').style.display = 'none';
    if (data.error) {
      document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">' + esc(data.error) + '</div>';
      return;
    }
    renderPart2(data);
  } catch(e) {
    document.getElementById('p2-loading').style.display = 'none';
    document.getElementById('p2-results').innerHTML = '<div style="background:var(--rdl);border-radius:8px;padding:.85rem;color:var(--rdt);font-size:12px;margin-top:.75rem">Part 2 failed. Please try again.</div>';
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
  (data.top_fixes||[]).forEach(function(f) {
    html += '<div class="fc"><div style="display:flex;gap:12px;align-items:flex-start"><div style="width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;background:var(--pul);color:var(--put)">' + (f.priority||'') + '</div>';
    html += '<div style="flex:1"><div style="font-size:13px;font-weight:500;margin-bottom:3px">' + esc(f.title||'') + '</div>';
    html += '<div style="font-size:12px;color:var(--mut);margin-bottom:4px;line-height:1.4">' + esc(f.why_it_matters||'') + '</div>';
    html += '<div style="font-size:11px;background:var(--bg);border-radius:6px;padding:5px 8px;color:var(--mut);line-height:1.5;margin-bottom:5px">' + esc(f.how_to_fix||'') + '</div>';
    html += '<span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px;background:var(--pul);color:var(--put)">' + esc(f.estimated_effort||'varies') + '</span>';
    html += '</div></div></div>';
  });
  var so = data.second_opinion || {};
  var soItems = [
    ['General second opinion', so.summary_prompt, 'ti-message-dots'],
    ['Security verification', so.security_prompt, 'ti-shield-check'],
    ['Production readiness', so.prod_checklist_prompt, 'ti-rocket']
  ];
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
</script>
</body>
</html>"""


if __name__ == "__main__":
    if not ANTHROPIC_API_KEY:
        print("\n⚠️  No ANTHROPIC_API_KEY in .env\n")
    print("🔍 Verilay running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
