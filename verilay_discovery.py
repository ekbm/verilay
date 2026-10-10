"""
verilay_discovery.py -- "similar open-source projects" for the paid deep scan.

Honest by construction:
  * Claude only (1) writes a few generic search phrases from the app's summary and
    (2) picks from REAL search results. It never names a project from memory, and
    any pick that is not in the results is discarded.
  * Only free, public, open-source GitHub repositories are searched, and the report
    says so (SCOPE_NOTE). Commercial and closed-source apps are not covered, so an
    empty list is never presented as "nothing similar exists".
  * Searches use generic category words only: no app name, repo name or code.
  * Any failure returns status "error" and the report simply omits the section.

Free analyses do NOT run this (it costs two Claude calls and several GitHub
searches); they carry a one-line pointer to the deep scan instead.
"""
import hashlib
import html as _html
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

SEARCH_URL = "https://api.github.com/search/repositories"
MAX_QUERIES = 3
MAX_PROJECTS = 6
POOL_SIZE = 12
MIN_STARS = 3            # filters out one-off student/demo repos
RECENT_MONTHS = 12       # ignore projects untouched for a year
CACHE_TTL = 24 * 3600

SCOPE_NOTE = ("These matches come from free, open-source projects on GitHub only. Commercial and closed-source "
              "apps are not included, so few or no matches does not mean nothing similar exists.")

_NOISE_NAME = ("awesome", "tutorial", "cheatsheet", "dotfiles", "interview", "roadmap", "course", "learn-",
               "-learning", "bootcamp", "leetcode")
_cache = {}
_cache_lock = threading.Lock()


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


# ---------------------------------------------------------------- Claude helpers

def _json_from(text):
    """First JSON object in a model reply (it may be wrapped in prose or code fences)."""
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


def _clean_query(q):
    q = re.sub(r"[^A-Za-z0-9 \-+.]", " ", str(q or ""))
    q = re.sub(r"\s+", " ", q).strip()
    return q if 3 <= len(q) <= 60 and "github" not in q.lower() else ""


def make_queries(call_claude_text, summary, built_with=""):
    prompt = (
        "You help a builder find similar existing OPEN-SOURCE projects on GitHub. Below is a short description "
        "of an app. Reply with JSON only, in exactly this shape:\n"
        '{"category": "<2-4 word category, e.g. AI log analysis>", "queries": ["...", "...", "..."]}\n\n'
        "Rules:\n"
        "- Give 3 GitHub search phrases of 2 to 5 plain words each, ordered from most specific to broadest.\n"
        "- Describe WHAT the app does and who it is for. Never include the app's name, any company, brand, "
        "person or website name.\n"
        "- No quotes, operators or punctuation. Mention a technology only if it is central to what the app is.\n\n"
        f"App description: {str(summary)[:900]}\n"
        f"Built with (hint only): {str(built_with)[:200]}\n"
    )
    data = _json_from(call_claude_text(prompt, 400)) or {}
    seen, queries = set(), []
    for q in data.get("queries") or []:
        q = _clean_query(q)
        if q and q.lower() not in seen:
            seen.add(q.lower())
            queries.append(q)
    category = re.sub(r"[^A-Za-z0-9 \-/&]", "", str(data.get("category") or "")).strip()[:40]
    return category, queries[:MAX_QUERIES]


def judge(call_claude_text, summary, candidates, max_n=MAX_PROJECTS):
    """Ask Claude which of the REAL candidates do the same job. Returns {full_name_lower: {why, best_at}}."""
    if not candidates:
        return {}
    lines = []
    for i, c in enumerate(candidates, 1):
        topics = ", ".join((c.get("topics") or [])[:6])
        lines.append(f"{i}. {c['full_name']} | {(c.get('description') or '')[:200]} | topics: {topics} | "
                     f"language: {c.get('language') or 'n/a'} | stars: {c.get('stargazers_count', 0)} | "
                     f"last updated: {str(c.get('pushed_at') or '')[:10]}")
    prompt = (
        "A builder wants to know which existing open-source projects do the same kind of job as their app.\n\n"
        f"Their app: {str(summary)[:900]}\n\nCandidate projects (real GitHub search results):\n"
        + "\n".join(lines) + "\n\n"
        f"Choose up to {max_n} candidates that genuinely do a similar job for a similar kind of user. Exclude "
        "libraries, frameworks, tutorials, lists, templates, datasets, research or benchmark code and generic developer "
        "tools unless the app itself is one of those. Prefer projects that are actively maintained. Choose FEWER, or none, if few are truly "
        "similar: a short honest list beats a padded one.\n\n"
        "Use ONLY the information above. Do not invent features or projects. Reply with JSON only:\n"
        '{"matches": [{"name": "owner/repo", "why": "one plain sentence, max 22 words, on what it has in common", '
        '"best_at": "one plain sentence, max 22 words, on what it appears strongest at, from the info above"}]}'
    )
    data = _json_from(call_claude_text(prompt, 1200)) or {}
    allowed = {c["full_name"].lower() for c in candidates}
    out = {}
    for m in data.get("matches") or []:
        name = str(m.get("name") or "").strip().lower()
        if name in allowed and name not in out:
            out[name] = {"why": str(m.get("why") or "").strip()[:200], "best_at": str(m.get("best_at") or "").strip()[:200]}
        if len(out) >= max_n:
            break
    return out


# ---------------------------------------------------------------- GitHub

def _search(query, token, session=requests):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30 * RECENT_MONTHS)).strftime("%Y-%m-%d")
    q = f"{query} archived:false fork:false stars:>={MIN_STARS} pushed:>={cutoff}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "verilay-discovery"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = session.get(SEARCH_URL, params={"q": q, "sort": "stars", "order": "desc", "per_page": POOL_SIZE},
                    headers=headers, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"GitHub search returned {r.status_code}")
    return r.json().get("items") or []


def gather_candidates(queries, token, self_repo="", search=_search):
    self_l = (self_repo or "").lower()
    self_owner = self_l.split("/")[0] if "/" in self_l else ""
    pool = {}
    for i, q in enumerate(queries):
        for rank, it in enumerate(search(q, token)):
            name = it.get("full_name") or ""
            low = name.lower()
            if not name or low == self_l or (self_owner and low.startswith(self_owner + "/")):
                continue
            if not (it.get("description") or "").strip():
                continue
            repo_part = low.split("/", 1)[-1]
            if any(n in repo_part for n in _NOISE_NAME):
                continue
            e = pool.setdefault(low, {"item": it, "hits": 0, "best_rank": rank})
            e["hits"] += 1
            e["best_rank"] = min(e["best_rank"], rank)
        if i < len(queries) - 1:
            time.sleep(0.3)  # stay well inside the search rate limit
    ranked = sorted(pool.values(), key=lambda e: (-e["hits"], -(e["item"].get("stargazers_count") or 0)))
    return [e["item"] for e in ranked[:POOL_SIZE]]


# ---------------------------------------------------------------- the entry point

def find_similar(call_claude_text, github_token, summary, built_with="", self_repo="", search=_search):
    """Returns {"status": "ok"|"none"|"error", "category", "projects": [...], "searched_at", "scope_note"}.
    Never raises."""
    key = hashlib.sha1(f"{(self_repo or '').lower()}|{summary}".encode("utf-8", "ignore")).hexdigest()
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    base = {"category": "", "projects": [], "searched_at": datetime.now(timezone.utc).isoformat(),
            "scope_note": SCOPE_NOTE}
    try:
        if not (summary or "").strip():
            return dict(base, status="none")
        category, queries = make_queries(call_claude_text, summary, built_with)
        base["category"] = category
        if not queries:
            return dict(base, status="none")
        cands = gather_candidates(queries, github_token, self_repo, search=search)
        picked = judge(call_claude_text, summary, cands)
        by_name = {c["full_name"].lower(): c for c in cands}
        projects = []
        for low, why in picked.items():
            c = by_name[low]
            lic = (c.get("license") or {}).get("spdx_id")
            projects.append({
                "name": c["full_name"], "url": c.get("html_url") or f"https://github.com/{c['full_name']}",
                "description": (c.get("description") or "").strip()[:220],
                "stars": c.get("stargazers_count") or 0, "language": c.get("language") or "",
                "license": None if lic in (None, "NOASSERTION") else lic,
                "pushed_at": c.get("pushed_at") or "", "why": why["why"], "best_at": why["best_at"],
            })
        result = dict(base, status="ok" if projects else "none", projects=projects)
    except Exception as e:  # discovery is a bonus section: never allowed to fail a scan
        print(f"[discovery] skipped: {type(e).__name__}: {e}", flush=True)
        return dict(base, status="error")
    with _cache_lock:
        _cache[key] = (now + CACHE_TTL, result)
    return result


# ---------------------------------------------------------------- rendering (report page)

def _ago(iso):
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return ""
    days = max(0, (datetime.now(timezone.utc) - d).days)
    if days < 8:
        return "updated this week"
    if days < 31:
        return f"updated {days // 7} weeks ago"
    if days < 365:
        return f"updated {days // 30} months ago"
    return "updated over a year ago"


def render_discovery_html(d):
    """The deep report's 'Similar open-source projects' card. '' when there is nothing to say."""
    if not d or d.get("status") not in ("ok", "none"):
        return ""
    tip = ('<div style="background:#F1EFE8;border-radius:8px;padding:.6rem .8rem;margin-top:.85rem;font-size:13px;'
           'color:#444"><strong>Tip:</strong> ' + _esc(d.get("scope_note") or SCOPE_NOTE) +
           " Check a project's licence before reusing any of its code.</div>")
    cat = f" Category: {_esc(d['category'])}." if d.get("category") else ""
    if d.get("status") == "none" or not d.get("projects"):
        body = ('<div style="font-size:13px;color:#555">No close open-source match turned up.' + cat +
                " That is useful to know, but it only covers free projects on GitHub.</div>")
        return '<div class="st">Similar open-source projects</div><div class="card">' + body + tip + "</div>"
    rows = ""
    for p in d["projects"]:
        facts = " &middot; ".join(x for x in (
            _esc(_ago(p.get("pushed_at"))), _esc(p.get("license") or "no licence listed"), _esc(p.get("language") or "")) if x)
        rows += (f'<div style="border-top:0.5px solid #e5e5f0;padding:.7rem 0">'
                 f'<a class="sp-link" href="{_esc(p["url"])}" target="_blank" rel="noopener" '
                 f'style="font-weight:600;color:#534AB7;text-decoration:none">{_esc(p["name"])}</a>'
                 f'<span style="font-size:12px;color:#888"> &nbsp;{facts}</span>'
                 f'<div style="font-size:13px;color:#555;margin-top:.2rem">{_esc(p.get("description"))}</div>'
                 + (f'<div style="font-size:13px;color:#444;margin-top:.25rem"><strong>Similar:</strong> {_esc(p["why"])}</div>' if p.get("why") else "")
                 + (f'<div style="font-size:13px;color:#444"><strong>Strongest at:</strong> {_esc(p["best_at"])}</div>' if p.get("best_at") else "")
                 + "</div>")
    intro = ('<div style="font-size:13px;color:#555;margin-bottom:.35rem">Projects that appear to do a similar job.' + cat +
             " Worth a look before you build more of the same, or to see what you could learn from or reuse.</div>")
    return '<div class="st">Similar open-source projects</div><div class="card">' + intro + rows + tip + "</div>"


def render_teaser_html():
    """One line for FREE reports of GitHub apps, pointing at the deep scan."""
    return ('<div style="font-size:13px;color:#555;margin:.75rem 0;padding:.6rem .85rem;background:#f8f8fc;'
            'border:0.5px solid #e5e5f0;border-radius:10px">Want to find out what similar apps already exist? '
            'The <a href="/deep-scan" style="color:#534AB7;font-weight:600">deep scan</a> includes a list of similar '
            'open-source projects.</div>')
