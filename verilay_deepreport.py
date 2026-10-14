"""
verilay_deepreport.py -- the parts of a report that are built from facts, not from the AI.

Three jobs, all added 2026-10-10 after reading a real deep-scan report (Loginsight):

1. build_dependency_fixes(): turn the OSV findings into one fix per PACKAGE, with a
   ready-to-paste prompt written from the data. The AI used to be asked to write
   these from a summary cut off at 3,000 characters, so it produced "run npm audit"
   for a list the report already contained.
2. mark_unchecked_layers(): a layer whose own summary says "no code was provided"
   was still shown as PASSING. It is now "not checked".
3. render_fixes_html(): the "Fix these first" section for the saved report page,
   with a Copy button on every prompt.

Pure functions over plain dicts, so they run (and are tested) without Flask,
Supabase or Claude.
"""
import html as _html
import re

_SEV_RANK = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4}


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


def _vkey(v):
    core = (v or "").split("-")[0].split("+")[0]
    return tuple(int(x) for x in re.findall(r"\d+", core)[:4])


def _major(v):
    k = _vkey(v)
    return k[0] if k else None


# ---------------------------------------------------------------- 1. dependency fixes

def _prompt_for_group(g):
    pkg, ver, tgt = g["package"], g["version_found"], g["target"]
    n = g["count"]
    ids = ", ".join(g["ids"][:6]) + (f" and {len(g['ids']) - 6} more" if len(g["ids"]) > 6 else "")
    issues = f"{n} known security issue{'s' if n != 1 else ''}"
    eco = g["ecosystem"]
    tool = {"npm": "npm package", "PyPI": "Python package"}.get(eco, "package")
    lines = [f'My security scan (Verilay) found {issues} in the {tool} "{pkg}", which my app uses at version {ver}. '
             f"Advisory IDs: {ids}."]
    if tgt:
        lines.append(f"The fix is to use version {tgt} or newer.")
    else:
        lines.append("No fixed version is listed yet, so please check the latest available version and whether "
                     "there is a safe alternative.")
    lines.append("")
    lines.append("Please:")
    if eco == "npm":
        lines.append(f'1. Check whether "{pkg}" is something I installed directly or comes in through another '
                     f"package (for example with `npm ls {pkg}`).")
        lines.append(f"2. If I installed it directly, update it to {tgt or 'the latest safe version'}"
                     f"{' or newer' if tgt else ''}. If it comes in through another package, update that parent "
                     f'package to a version that uses a fixed "{pkg}", or add an `overrides` entry in package.json. '
                     "Do not edit files inside node_modules.")
    elif eco == "PyPI":
        lines.append(f'1. Check whether "{pkg}" is listed directly in my requirements file or comes in through '
                     f"another package (for example with `pip show {pkg}`).")
        lines.append(f"2. Update it to {tgt or 'the latest safe version'}{' or newer' if tgt else ''} and pin the "
                     "new version in my requirements file.")
    else:
        lines.append(f'1. Check where "{pkg}" is used and whether it is a direct or indirect dependency.')
        lines.append(f"2. Update it to {tgt or 'the latest safe version'}{' or newer' if tgt else ''}.")
    step = 3
    if g["major_jump"]:
        lines.append(f"{step}. Careful: this is a jump from version {_major(ver)}.x to {_major(tgt)}.x, which can "
                     f"break things. First check whether a fixed version exists inside the {_major(ver)}.x line, "
                     "or whether updating the parent package solves it more safely. If the build breaks, undo the "
                     "change and tell me.")
        step += 1
    lines.append(f"{step}. Run the build (and any tests) and tell me in plain English what changed and whether "
                 "anything stopped working.")
    if g["is_dev"]:
        lines.append("")
        lines.append("Note: this is a development/build tool, not part of what my visitors use, so treat it as "
                     "lower priority than packages that ship to users.")
    return "\n".join(lines)


def _all_prompt(runtime, dev):
    def line(g):
        tgt = g["target"] or "latest safe version"
        extra = " [major version jump: check for a same-line fix first]" if g["major_jump"] else ""
        return (f"- {g['package']}: {g['version_found']} -> {tgt} "
                f"({g['count']} issue{'s' if g['count'] != 1 else ''}, {g['severity']}){extra}")
    out = ["My security scan (Verilay) found known security issues in packages my app uses. Please fix them one "
           "package at a time, running the build and any tests after each one, and tell me in plain English what "
           "you changed.", ""]
    if runtime:
        out.append("Packages that ship to my users (higher priority):")
        out.extend(line(g) for g in runtime)
        out.append("")
    if dev:
        out.append("Build and test tools only (lower priority, do these last):")
        out.extend(line(g) for g in dev)
        out.append("")
    out.append("For each package: first check whether I installed it directly or it comes in through another "
               "package. If it is indirect, update the parent package or add an `overrides` entry instead of editing "
               "node_modules. If an update is a major version jump, check for a fix inside the current major "
               "version first, and stop and ask me before making a change that breaks the build.")
    return "\n".join(out)


def build_dependency_fixes(vulns):
    """vulns: the dicts in report["osv_scan"]["vulnerabilities"]. One entry per
    (package, installed version), runtime packages first, worst first."""
    groups = {}
    order = []
    for v in vulns or []:
        key = (v.get("ecosystem") or "", v.get("package") or "", v.get("version_found") or "")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(v)

    out = []
    for key in order:
        eco, pkg, ver = key
        items = groups[key]
        found_key = _vkey(ver)
        # A "fix" at or below the installed version is bad data, never advice.
        usable = [x["fixed_version"] for x in items
                  if x.get("fixed_version") and (not found_key or _vkey(x["fixed_version"]) > found_key)]
        target = max(usable, key=_vkey) if usable else None
        worst = min((x.get("severity") or "unknown" for x in items), key=lambda s: _SEV_RANK.get(s, 9))
        is_dev = all(bool(x.get("is_dev")) for x in items)
        major_jump = bool(target and found_key and _major(target) != _major(ver))
        ids = []
        for x in items:
            if x.get("id") and x["id"] not in ids:
                ids.append(x["id"])
        n = len(items)
        first_summary = (items[0].get("summary") or "").strip()
        g = {
            "package": pkg, "ecosystem": eco, "version_found": ver, "target": target,
            "count": n, "ids": ids, "severity": worst, "is_dev": is_dev, "major_jump": major_jump,
            "unfixed": len(usable) < n,
        }
        g["title"] = (f"Update {pkg} {ver} → {target}" if target
                      else f"{pkg} {ver}: no fixed version listed")
        why = f"{n} known issue{'s' if n != 1 else ''} (worst: {worst}). {first_summary[:160]}".strip()
        if is_dev:
            why += " This is a build/test tool, not shipped to your users, so it is lower priority."
        g["why"] = why
        g["effort"] = "30–60 minutes (test carefully)" if major_jump else "5–15 minutes"
        g["prompt"] = _prompt_for_group(g)
        out.append(g)

    out.sort(key=lambda g: (g["is_dev"], _SEV_RANK.get(g["severity"], 9), -g["count"], g["package"]))
    runtime = [g for g in out if not g["is_dev"]]
    dev = [g for g in out if g["is_dev"]]
    return {"groups": out, "runtime_count": len(runtime), "dev_count": len(dev),
            "all_prompt": _all_prompt(runtime, dev) if out else ""}


def drop_dependency_fixes(top_fixes, vulns):
    """The AI is told not to write dependency fixes, but if it does anyway, drop
    them: the deterministic ones replace them. Matches on a vulnerable package
    name, an advisory id, or the phrases it uses for 'go run an audit'."""
    names = {(v.get("package") or "").lower() for v in vulns or [] if len(v.get("package") or "") >= 4}
    kept = []
    for f in top_fixes or []:
        text = " ".join(str(f.get(k, "")) for k in ("title", "why_it_matters", "how_to_fix", "lovable_prompt")).lower()
        if "ghsa-" in text or "npm audit" in text or "pip-audit" in text or any(n in text for n in names):
            continue
        kept.append(f)
    for i, f in enumerate(kept, 1):
        f = dict(f)
        f["priority"] = str(i)
        kept[i - 1] = f
    return kept


# ---------------------------------------------------------------- 2. layers never seen

class _NotProvided:
    """Does this layer summary say the AI never read code for the layer? Forms that count:
      * "No authentication code was provided ...", "No authentication mechanisms were found ..." (at the start)
      * "... was/were not (directly) provided / reviewed / examined ..." in the first sentence
      * "no database configuration files ... were directly reviewed", "none of the batches examined ..."
    A summary about PROBLEMS ("No issues found in the auth code", "No critical vulnerabilities found", "No hardcoded
    secrets found in any of the 35 files reviewed") says the opposite: the code was read and is healthy. Found
    2026-10-14: the plain pattern read those healthy sentences as "never seen", so clean layers showed "Not checked";
    and on the Juice Shop report phrasings such as "were not directly reviewed" were missed, so layers whose own text
    said the code was not read still showed a green "passing"."""
    _verbs = (r"provided|supplied|included|reviewed|examined|inspected|seen|visible|available")
    _seen_nothing = re.compile(
        r"^\s*(?:no|none of the)\b([^.;]{0,80}?)\b(?:provided|supplied|included|found|present|visible|available|"
        r"reviewed|seen|submitted)\b", re.I)
    _about_problems = re.compile(
        r"\b(?:issues?|vulnerabilit\w*|problems?|findings?|weakness\w*|concerns?|risks?|flaws?|bugs?|"
        r"misconfigur\w*|errors?|hardcoded|secrets?|credentials?|injection|exposure|exposed|leaks?|leaked|xss|csrf|cves?)\b",
        re.I)
    _not_read = re.compile(
        r"\b(?:was|were|is|are|been|could|can)\s+not\s+(?:be\s+)?(?:directly\s+|actually\s+|specifically\s+|fully\s+)?"
        r"(?:provided|supplied|included|reviewed|examined|inspected|seen|visible|available|analy[sz]ed)\b", re.I)
    _none_examined = re.compile(
        r"\bnone\s+(?:of\s+the\s+)?(?:batches\s+|files\s+)?(?:examined|reviewed|inspected|looked\s+at)\b", re.I)
    _no_then_read = re.compile(
        r"\bno\b([^.;]{0,120}?)\b(?:provided|supplied|included|reviewed|examined|inspected|seen|visible|available)\b", re.I)

    def search(self, text):
        t = (text or "").strip()
        m = self._seen_nothing.search(t)
        if m and not self._about_problems.search(m.group(1)):
            return m
        first = re.split(r"(?<=[.!?])\s", t, maxsplit=1)[0][:400]
        for rx in (self._not_read, self._none_examined):
            m = rx.search(first)
            if m:
                return m
        m = self._no_then_read.search(first)
        if m and not self._about_problems.search(m.group(1)):
            return m
        return None


_NOT_PROVIDED = _NotProvided()


def _batch_layers(raw_results):
    """Every (layer dict) the batch reviews produced, from both the Auth/Config/Database and the API/Frontend/
    Libraries passes."""
    for entry in raw_results or []:
        for key in ("step2", "step3"):
            for layer in ((entry.get(key) or {}).get("layers") or []):
                yield layer


def layers_with_code_evidence(raw_results):
    """{layer name: the batch's own review of it} for every layer where at least one batch's AI described real
    code (its summary is not empty, not the 'X layer analysis.' filler, and not 'No X code was provided').
    This is the proof a layer WAS read, however clean it turned out to be."""
    best = {}
    for layer in _batch_layers(raw_results):
        name = layer.get("name") or ""
        ex = layer.get("expert") or {}
        summ = (ex.get("summary") or "").strip()
        if not name or not summ or summ == f"{name} layer analysis." or _NOT_PROVIDED.search(summ):
            continue
        richness = len(summ) + len(((layer.get("learner") or {}).get("what_it_does_in_your_app") or ""))
        if name not in best or richness > best[name][0]:
            best[name] = (richness, layer)
    return {n: v[1] for n, v in best.items()}


def restore_clean_layers(merged_layers, raw_results):
    """The merge step is only handed each layer's PROBLEMS, so a healthy layer reached it as an empty list and came
    back as 'No <layer> code was found', which the 'not checked' detector then read as 'never seen'. A layer that
    some batch really read, and that has no real findings after merging, gets that batch's own description back
    (summary and the plain-English narrative) and stays PASSING. Returns the names of layers with evidence."""
    seen = layers_with_code_evidence(raw_results)
    for layer in (merged_layers or {}).get("layers", []):
        name = layer.get("name")
        src = seen.get(name)
        if name == "Libraries" or not src:
            continue
        ex = layer.get("expert") or {}
        findings = ex.get("findings") or []
        has_real = any((f.get("title") or "") not in ("", "No issues found") for f in findings)
        summ = (ex.get("summary") or "").strip()
        if summ and summ != f"{name} layer analysis." and not _NOT_PROVIDED.search(summ):
            continue   # the merge already described it properly
        sex = src.get("expert") or {}
        ex["summary"] = sex.get("summary") or summ
        layer["expert"] = ex
        if not has_real:   # a layer that has findings keeps its status (and its findings)
            layer["status"] = "passing"
        lrn, slrn = layer.get("learner") or {}, src.get("learner") or {}
        for k in ("what_is_it", "analogy", "what_it_does_in_your_app", "how_it_connects", "key_concept"):
            if slrn.get(k) and (not lrn.get(k) or k in ("what_is_it", "what_it_does_in_your_app", "how_it_connects")):
                lrn[k] = slrn[k]
        layer["learner"] = lrn
        if src.get("app_label") and not layer.get("app_label"):
            layer["app_label"] = src["app_label"]
        if src.get("connects_to") and not layer.get("connects_to"):
            layer["connects_to"] = list(src["connects_to"])
        if src.get("quiz") and not (layer.get("quiz") or [{}])[0].get("question"):
            layer["quiz"] = src["quiz"]
    return set(seen)


_LAYER_SEV_RANK = {"passing": 0, "info": 0, "low": 0, "warning": 1, "moderate": 1, "medium": 1, "high": 2, "critical": 2}


def align_layer_status(merged_layers):
    """A layer's status chip can never be calmer than its own worst finding: a layer holding a critical finding is
    critical, one holding a warning is at least warning (the merge sometimes left such a layer on a green "passing").
    Only ever raises a status; Libraries (set from the package data) and not_checked layers are left alone.
    Returns the names changed."""
    changed = []
    for layer in (merged_layers or {}).get("layers", []):
        if layer.get("name") == "Libraries" or layer.get("status") == "not_checked":
            continue
        worst = max([_LAYER_SEV_RANK.get((f.get("severity") or "").lower(), 0)
                     for f in ((layer.get("expert") or {}).get("findings") or [])] or [0])
        status = layer.get("status")
        if worst == 2 and status != "critical":
            layer["status"] = "critical"; changed.append(layer.get("name"))
        elif worst == 1 and status == "passing":
            layer["status"] = "warning"; changed.append(layer.get("name"))
    return changed


PARTIAL_NOTE = ("Note: Verilay's AI review did not read dedicated code for this area, so treat this result as "
                "partial. ")


def note_partly_read_layers(merged_layers, layers_read=None):
    """A layer whose own text says its code was not read, but which still has findings (so it cannot honestly be
    "Not checked": its findings are real, for example from the automatic key and package scans), keeps those findings
    and gets a plain note saying the AI review did not read code for it. Layers some batch really read are left alone.
    Returns the names noted."""
    noted = []
    for layer in (merged_layers or {}).get("layers", []):
        name = layer.get("name")
        if name == "Libraries" or layer.get("status") == "not_checked":
            continue
        if layers_read is not None and name in layers_read:
            continue
        ex = layer.get("expert") or {}
        summ = ex.get("summary") or ""
        has_real = any((f.get("severity") or "").lower() in ("critical", "warning", "high", "moderate")
                       for f in (ex.get("findings") or []))
        if has_real and _NOT_PROVIDED.search(summ) and not summ.startswith(PARTIAL_NOTE):
            ex["summary"] = PARTIAL_NOTE + summ
            layer["expert"] = ex
            noted.append(name)
    return noted


def mark_unchecked_layers(merged_layers, files_read=None, layers_read=None):
    """If a layer's own summary opens with 'No <layer> code was provided...' and it
    has no real findings, the AI never saw that layer. Showing PASSING there tells
    a buyer something was verified when nothing was. Flags those layers
    'not_checked' (and returns their names). Libraries is never touched: its
    verdict comes from the OSV data, not from reading files. `layers_read` = names of layers some
    batch really read (layers_with_code_evidence): those are never flagged."""
    names = []
    for layer in (merged_layers or {}).get("layers", []):
        if layer.get("name") == "Libraries":
            continue
        if layers_read is not None and layer.get("name") in layers_read:
            continue
        ex = layer.get("expert") or {}
        findings = ex.get("findings") or []
        has_real = any((f.get("severity") or "").lower() in ("critical", "warning") for f in findings)
        only_placeholder = all(((f.get("title") or "") == "No issues found") or
                               (f.get("severity") or "").lower() == "passing" for f in findings)
        if has_real or not only_placeholder or not _NOT_PROVIDED.search(ex.get("summary") or ""):
            continue
        # A layer with substantive passing findings (it DID see something) keeps its status.
        substantive = [f for f in findings if (f.get("title") or "") not in ("", "No issues found")]
        if substantive:
            continue
        name = layer.get("name", "")
        seen = f" among the {files_read} files it read" if files_read else ""
        ex["findings"] = [{
            "severity": "not_checked",
            "title": "Not checked",
            "detail": (f"Verilay did not see any {name.lower()} code{seen}, so it cannot say whether this layer "
                       "is healthy. Do not read this as a pass."),
            "file": "", "why_it_matters": "",
        }]
        layer["expert"] = ex
        layer["status"] = "not_checked"
        if isinstance(layer.get("learner"), dict):
            layer["learner"]["findings_plain"] = []
        names.append(name)
    return names


# ---------------------------------------------------------------- 3. the "Fix these first" section

_SEV_STYLE = {"critical": ("#FCEBEB", "#A32D2D"), "high": ("#FCEBEB", "#A32D2D"),
              "warning": ("#FEF3C7", "#92400E"), "moderate": ("#FEF3C7", "#92400E"),
              "low": ("#F1EFE8", "#5F5E5A"), "unknown": ("#F1EFE8", "#5F5E5A")}

_COPY_SCRIPT = (
    "<script>document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.cp');"
    "if(!b)return;var el=document.getElementById(b.getAttribute('data-target'));if(!el)return;"
    "var t=el.innerText||el.textContent;var done=function(m){b.textContent=m;"
    "setTimeout(function(){b.textContent='Copy prompt'},2000)};"
    "var fallback=function(){var r=document.createRange();r.selectNodeContents(el);var s=window.getSelection();"
    "s.removeAllRanges();s.addRange(r);done('Selected: press Ctrl+C')};"
    "if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(function(){done('Copied')},fallback)}"
    "else{fallback()}});</script>"
)


def _pill(text, sev):
    bg, fg = _SEV_STYLE.get(sev, _SEV_STYLE["unknown"])
    return (f'<span style="background:{bg};color:{fg};font-size:11px;font-weight:600;padding:2px 8px;'
            f'border-radius:20px;margin-left:6px;text-transform:uppercase">{_esc(text)}</span>')


def _prompt_block(pid, prompt):
    return (f'<div style="font-size:12px;color:#888;margin-top:.5rem">Prompt for your AI builder:</div>'
            f'<div class="pb" id="{pid}">{_esc(prompt)}</div>'
            f'<button type="button" class="cp" data-target="{pid}" style="margin-top:.4rem;font-size:12px;'
            f'padding:5px 12px;border-radius:20px;border:0.5px solid #534AB7;background:#fff;color:#534AB7;'
            f'cursor:pointer">Copy prompt</button>')


def _dep_group_html(g, idx):
    tags = ""
    if g["major_jump"]:
        tags += _pill("major version jump", "warning")
    pill = _pill("dev tool" if g["is_dev"] else g["severity"], "low" if g["is_dev"] else g["severity"])
    return (f'<details class="fix"><summary style="cursor:pointer;font-weight:600">{_esc(g["title"])}{pill}{tags}</summary>'
            f'<div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">{_esc(g["why"])}</div>'
            f'<div style="font-size:12px;color:#888">Effort: {_esc(g["effort"])} &nbsp;&middot;&nbsp; Advisories: {_esc(", ".join(g["ids"][:8]))}</div>'
            f'{_prompt_block(f"dp{idx}", g["prompt"])}</details>')


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def render_authz_html(authz):
    """The saved report's "Who can do what" section. Free reports carry counts and ONE example; deep reports
    carry every finding with a ready-to-paste fix. Returns "" when the check did not apply (no Supabase files)."""
    if not isinstance(authz, dict) or not authz.get("applicable"):
        return ""
    crit, review = int(authz.get("critical") or 0), int(authz.get("review") or 0)
    sc = authz.get("scope") or {}
    note = (f'<div style="font-size:12px;color:#888;margin-top:.6rem">{_esc(authz.get("scope_note", ""))}</div>')
    head = '<div class="st">Who can do what</div><div class="card">'
    if not crit and not review:
        read = ", ".join(x for x in (
            _plural(int(sc.get("tables") or 0), "table", "tables") if sc.get("tables") else "",
            _plural(int(sc.get("database_functions") or 0), "database action", "database actions") if sc.get("database_functions") else "",
            _plural(int(sc.get("backend_functions") or 0), "backend function", "backend functions") if sc.get("backend_functions") else "") if x)
        return (head + '<strong style="color:#1D9E75">&#10003; No obvious access problems found</strong>'
                + (f'<div style="font-size:13px;color:#666;margin-top:.35rem">Read {_esc(read)}.</div>' if read else "")
                + note + '</div>')
    color = "#A32D2D" if crit else "#92400E"
    headline = ((_plural(crit, "serious access problem", "serious access problems") + " found"
                 + (f" &middot; {review} more to check" if review else "")) if crit
                else _plural(review, "place", "places") + " to check")
    findings = authz.get("findings")
    if findings is None:   # free report: counts and one example
        ex = authz.get("example") or {}
        body = ""
        if ex:
            body = (f'<div style="margin-top:.5rem"><strong>{_esc(ex.get("title", ""))}</strong>'
                    f'<div style="font-size:13px;color:#555;margin-top:.2rem">{_esc(ex.get("plain", ""))} '
                    f'<span style="font-family:monospace;font-size:12px">{_esc(ex.get("file", ""))}</span></div></div>')
        return (head + f'<strong style="color:{color}">{headline}</strong>' + body
                + '<div style="font-size:13px;color:#555;margin-top:.6rem">The <a href="/deep-scan" style="color:#534AB7">deep scan</a> '
                  'lists every one with a ready-to-paste fix for your AI builder.</div>' + note + '</div>')
    parts = [head, f'<strong style="color:{color}">{headline}</strong>',
             '<div style="font-size:13px;color:#555;margin:.35rem 0 .5rem">Copy a prompt, paste it into your AI builder, '
             'then re-run Verilay. Serious ones are clear-cut; &ldquo;please check&rdquo; ones may be intended, so confirm with your AI builder.</div>']
    for i, f in enumerate(findings):
        serious = f.get("level") == "definite"
        parts.append(
            f'<details class="fix"><summary style="cursor:pointer;font-weight:600">{_esc(f.get("title", ""))}'
            f'{_pill("serious" if serious else "please check", "critical" if serious else "warning")}</summary>'
            f'<div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">{_esc(f.get("plain", ""))}</div>'
            f'<div style="font-size:12px;color:#888">Where: <span style="font-family:monospace">{_esc(f.get("file", ""))}'
            f'{(" line " + str(f.get("line"))) if f.get("line") else ""}</span></div>'
            f'{_prompt_block(f"az{i}", f.get("fix_prompt", "")) if f.get("fix_prompt") else ""}</details>')
    parts.append(note + '</div>')
    return "".join(parts)


def render_fixes_html(data):
    """The saved report's 'Fix these first' section. Returns '' when there is nothing to fix."""
    fixes = data.get("top_fixes") or []
    dep = data.get("dependency_fixes") or {}
    groups = dep.get("groups") or []
    if not fixes and not groups:
        return ""

    parts = ['<div class="st">Fix these first</div><div class="card">',
             '<div style="font-size:13px;color:#555;margin-bottom:.5rem">Copy a prompt, paste it into your AI '
             'builder (Lovable, Replit, Bolt, Cursor&hellip;), then re-run Verilay to check it worked. '
             'Treat each one as something to verify, not an order: your AI builder knows your code.</div>']

    ai_html = ""
    for i, f in enumerate(fixes):
        prompt = f.get("lovable_prompt") or f.get("general_prompt") or ""
        sev = (f.get("severity") or "warning").lower()
        ai_html += (f'<details class="fix"><summary style="cursor:pointer;font-weight:600">{_esc(f.get("priority", ""))}. '
                    f'{_esc(f.get("title", ""))}{_pill(sev, sev)}</summary>'
                    f'<div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">{_esc(f.get("why_it_matters", ""))}</div>'
                    f'<div style="font-size:13px;color:#444"><strong>How:</strong> {_esc(f.get("how_to_fix", ""))}</div>'
                    f'<div style="font-size:12px;color:#888">Effort: {_esc(f.get("estimated_effort", ""))}</div>'
                    f'{_prompt_block(f"fp{i}", prompt) if prompt else ""}</details>')

    dep_html = ""
    if groups:
        runtime = [g for g in groups if not g["is_dev"]]
        dev = [g for g in groups if g["is_dev"]]
        dep_html += ('<div style="font-size:13px;font-weight:600;margin:.9rem 0 .25rem">Packages to update '
                     f'({len(groups)} packages, from {sum(g["count"] for g in groups)} known issues)</div>')
        if len(groups) >= 2:
            dep_html += ('<details class="fix" open><summary style="cursor:pointer;font-weight:600">Update everything with '
                         'one prompt</summary><div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">The quickest '
                         'route: one prompt that lists every package below, live-app packages first.</div>'
                         f'{_prompt_block("dpall", dep.get("all_prompt", ""))}</details>')
        idx = 0
        for g in runtime:
            dep_html += _dep_group_html(g, idx)
            idx += 1
        if dev:
            dep_html += (f'<div style="font-size:12px;color:#888;margin:.75rem 0 .25rem">Build and test tools only '
                         f'({len(dev)}): not shipped to your users, so lower priority</div>')
            for g in dev:
                dep_html += _dep_group_html(g, idx)
                idx += 1

    # Package updates lead when something that ships to users is high or critical.
    dep_first = any((not g["is_dev"]) and g["severity"] in ("critical", "high") for g in groups) and \
        not any((f.get("severity") or "").lower() == "critical" for f in fixes)
    parts.append((dep_html + ai_html) if dep_first else (ai_html + dep_html))
    parts.append("</div>")
    parts.append(_COPY_SCRIPT)
    return "".join(parts)
