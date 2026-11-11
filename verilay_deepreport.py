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

from verilay_fixtags import label as _fix_label, anchor as _fix_anchor
import verilay_selfcheck as _selfcheck

_SEV_RANK = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4}


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


# ---------------------------------------------------------------- "what could this break?" (2 Nov 2026)
# Moses fixed a real app's critical problem with a Verilay prompt: closing the gap alone would have silently stopped
# its monthly scheduled email, which only got through BECAUSE of the gap. The AI builder noticed only because the
# prompt asked how the code was triggered. Every fix prompt now ends with this step, so the AI checks what works
# today before changing it, and says how to test it afterwards. Added once (old saved prompts get it when shown).
#
# 9 Nov 2026 (Moses: Verilay's prompts "should use the same reasoning" as the hand-written ones for a real app): the step
# grew into the full "explain first" questions, the same ones the blog's "Understand Before You Fix" teaches, and each
# prompt now has a separate Step 2 (GO_AHEAD) to paste only after the explanation makes sense. Old saved prompts that
# end with the shorter step get the new one instead when shown.
SAFETY_STEP = ("Please don't change anything yet. In plain English, tell me:\n"
               "1. Is this really a problem? Show me the exact file and lines.\n"
               "2. Who could misuse it, and what could they see or do?\n"
               "3. How is this part meant to be used? What relies on it working the way it does now: other pages, a "
               "mobile app that is already released, scheduled jobs, webhooks, emails, payments or sign-in?\n"
               "4. What could the fix break, and how would we avoid that?\n"
               "5. How will we check afterwards that everything still works, on the website and in the mobile app if "
               "there is one?\n"
               "Also check the whole app for the same kind of problem, and list every place with the file and line.\n"
               "Don't change anything until I reply.")
_SAFETY_MARK = "Don't change anything until I reply."
_OLD_SAFETY_STEP = ("First, before making any change: list what works today that this change could stop working, such as "
                    "scheduled jobs, webhooks, emails, payments, sign-in or admin buttons. Keep all of those working. After "
                    "the change, tell me exactly how to check that each one still works.")
# Code fitness tidy-ups (no security problem, nobody "misusing" anything): the same care, without the security questions.
TIDY_STEP = ("Please don't change anything yet. In plain English, tell me:\n"
             "1. What exactly would this tidy-up change, file by file?\n"
             "2. What relies on this code working the way it does now: other pages, a mobile app that is already released, "
             "scheduled jobs, webhooks, emails, payments or sign-in?\n"
             "3. What could the tidy-up break, and how would we avoid that?\n"
             "4. How will we check afterwards that everything still works?\n"
             "Don't change anything until I reply.")
# Step 2 (11 Nov 2026): safe even when pasted without reading. Fix only this place (a Step 1 answer often lists many),
# never publish before a preview test, and remember a released mobile app that loads the website.
GO_AHEAD = ("Thanks. Please fix only the place named in this report, not the other places you listed: we'll do those separately, one "
            "at a time. Keep everything you listed working. Don't publish or deploy anything. I'll test it in the preview first. "
            "Then tell me exactly what you changed, file by file, and walk me through the checks from your answer so I can confirm "
            "everything still works. If there's a mobile app that's already released, remind me to test it after publishing.")
FIX_PROMPT_KEYS = ("general_prompt", "lovable_prompt", "replit_prompt", "fix_prompt")


def with_safety_step(prompt, step=None):
    """The prompt with the "explain first" questions (SAFETY_STEP, or TIDY_STEP for a tidy-up) at the end, once; an older
    prompt's shorter step is replaced. Empty stays empty."""
    p = str(prompt or "").replace(_OLD_SAFETY_STEP, "").rstrip()
    if not p or _SAFETY_MARK in p:
        return p
    return p + "\n\n" + (step or SAFETY_STEP)


def fallback_prompt(fix):
    """A Step 1 prompt built from a fix's own title and reason, for a fix the AI listed but did not finish writing a
    prompt for (9 Nov 2026: a big app's 4th fix arrived with no prompt when the AI ran out of room). Verilay's explain-first
    questions are added to it like any other prompt. Empty when the fix has no title."""
    if not isinstance(fix, dict) or not str(fix.get("title") or "").strip():
        return ""
    why = str(fix.get("why_it_matters") or "").strip()
    return (f"I received a security review flagging this problem: {str(fix['title']).strip()}."
            + (f" Details from the review: {why}" if why else "")
            + " Please review and advise without making changes yet.")


def fixes_with_safety_step(fixes):
    """Copies of the fixes with SAFETY_STEP on every prompt they carry."""
    out = []
    for f in fixes or []:
        if isinstance(f, dict):
            f = dict(f)
            for k in FIX_PROMPT_KEYS:
                if f.get(k):
                    f[k] = with_safety_step(f[k])
        out.append(f)
    return out


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


# Folders that hold tools next to an app, not the app itself (a video maker, docs, examples, test suites). A package found
# ONLY in such folders never reaches the app's users. A folder not on this list (frontend/, backend/, apps/web...) may be
# the real app, so it is never assumed to be a side folder.
SIDE_FOLDERS = {"remotion", "video", "videos", "docs", "doc", "documentation", "examples", "example", "demo", "demos",
                "scripts", "tools", "e2e", "tests", "test", "__tests__", "cypress", "playwright", "benchmark", "benchmarks",
                "storybook", ".storybook", "playground", "fixtures", ".github", "website-docs"}


def side_folder(found_in):
    """The side folder (e.g. "remotion") when EVERY place the package was found is inside one, else ""."""
    tops = set()
    for f in found_in or []:
        top = str(f or "").strip("/").split("/")[0].lower()
        if not top or top not in SIDE_FOLDERS:
            return ""
        tops.add(top)
    return sorted(tops)[0] if tops else ""


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
        found_in = sorted({f for x in items for f in (x.get("found_in") or [])})
        ids = []
        for x in items:
            if x.get("id") and x["id"] not in ids:
                ids.append(x["id"])
        n = len(items)
        first_summary = (items[0].get("summary") or "").strip()
        g = {
            "package": pkg, "ecosystem": eco, "version_found": ver, "target": target,
            "count": n, "ids": ids, "severity": worst, "is_dev": is_dev, "major_jump": major_jump,
            "unfixed": len(usable) < n, "found_in": found_in, "side_folder": side_folder(found_in),
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
        if layer.get("status") == "not_checked":   # the batch's answer never covered this layer
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


def _prompt_block(pid, prompt, kind="fix"):
    """A copyable Step 1 prompt plus its Step 2 (go ahead). kind="tidy" for Code fitness tidy-ups."""
    prompt = with_safety_step(prompt, TIDY_STEP if kind == "tidy" else None)
    btn = ('style="margin-top:.4rem;font-size:12px;padding:5px 12px;border-radius:20px;border:0.5px solid #534AB7;'
           'background:#fff;color:#534AB7;cursor:pointer"')
    return (f'<div style="font-size:12px;color:#888;margin-top:.5rem"><strong>Step 1:</strong> paste this into your AI '
            f'builder. It explains the problem first and changes nothing.</div>'
            f'<div class="pb" id="{pid}">{_esc(prompt)}</div>'
            f'<button type="button" class="cp" data-target="{pid}" {btn}>Copy prompt</button>'
            f'<div style="font-size:12px;color:#888;margin-top:.7rem"><strong>Step 2:</strong> only when its answer makes '
            f'sense to you, paste this to let it make the change.</div>'
            f'<div class="pb" id="{pid}-go">{_esc(GO_AHEAD)}</div>'
            f'<button type="button" class="cp" data-target="{pid}-go" {btn}>Copy prompt</button>')


def _dep_group_html(g, idx):
    tags = ""
    if g["major_jump"]:
        tags += _pill("major version jump", "warning")
    pill = _pill("dev tool" if g["is_dev"] else g["severity"], "low" if g["is_dev"] else g["severity"])
    if g.get("side_folder"):
        tags += _pill(f'side folder {g["side_folder"]}/', "low")
    return (f'<details class="fix" id="dpg{idx}"><summary style="cursor:pointer;font-weight:600">{_esc(g["title"])}{pill}{tags}</summary>'
            f'<div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">{_esc(g["why"])}</div>'
            f'<div style="font-size:12px;color:#888">Effort: {_esc(g["effort"])} &nbsp;&middot;&nbsp; Advisories: {_esc(", ".join(g["ids"][:8]))}</div>'
            f'{_prompt_block(f"dp{idx}", g["prompt"])}</details>')


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


# ---------------------------------------------------------------- 4. "Your plan" (2 Nov 2026)
# Moses: a deep report with 2 criticals, 26 warnings and 55 package issues left him asking "which first? do I need all of
# them?", and most users won't ask. "Your plan" sorts everything into three groups, at the top of the deep report. It
# follows his Code fitness rule: only suggest changing working code when it is worth the risk. The grade is unchanged.
#   Do now           critical code fixes; at most PLAN_NOW_PACKAGES serious package updates that are a small step and
#                    may reach users
#   Worth doing later  other code fixes; serious packages needing a big version jump (can break things); moderate ones
#                    that may reach users; serious ones beyond the Do-now limit
#   Can wait         packages CONFIRMED as build/test tools, packages found only in a side folder, and low-risk ones
# Not sure whether a package reaches users? It never goes in "Can wait" unless it is low risk.
PLAN_NOW_PACKAGES = 3


def build_plan(data, fixes_url="", packages_url=""):
    """{"now": [...], "later": [...], "wait": [...], "wait_groups": {...}} or None when there is nothing to sort. Each item:
    {"title", "kind": "fix"|"package", "note", "href"}. `fixes_url` / `packages_url` put the links on the deep report's
    own pages (the anchors are the same there)."""
    fixes = [f for f in (data.get("top_fixes") or []) if isinstance(f, dict) and f.get("title")]
    dep = data.get("dependency_fixes") or {}
    groups = [g for g in (dep.get("groups") or []) if isinstance(g, dict)]
    if not fixes and not groups:
        return None
    now, later, wait = [], [], []
    wait_groups = {"tools": 0, "side": {}, "low": 0}
    for i, f in enumerate(fixes):
        item = {"title": str(f.get("title")), "kind": "fix", "note": "", "href": fixes_url + "#" + _fix_anchor(f, i)}
        (now if (f.get("severity") or "").lower() == "critical" else later).append(item)
    serious_small = []
    for idx, g in enumerate(_ordered_groups(groups)):
        item = {"title": g.get("title") or f'Update {g.get("package")}', "kind": "package", "note": "",
                "href": f"{packages_url}#dpg{idx}"}
        sev = g.get("severity") or "unknown"
        if g.get("side_folder"):
            item["note"] = f'side folder {g["side_folder"]}/, not part of your app'
            wait.append(item)
            wait_groups["side"][g["side_folder"]] = wait_groups["side"].get(g["side_folder"], 0) + 1
        elif g.get("is_dev"):
            item["note"] = "build or test tool, never reaches your users"
            wait.append(item)
            wait_groups["tools"] += 1
        elif sev in ("critical", "high") and not g.get("major_jump") and g.get("target"):
            item["note"] = "small safe step, may reach your users"
            serious_small.append(item)
        elif sev in ("critical", "high"):
            item["note"] = "big version jump: can break things" if g.get("major_jump") else "no fixed version yet"
            later.append(item)
        elif sev in ("moderate", "unknown"):
            item["note"] = "big version jump: can break things" if g.get("major_jump") else "may reach your users"
            later.append(item)
        else:
            item["note"] = "low risk"
            wait.append(item)
            wait_groups["low"] += 1
    now.extend(serious_small[:PLAN_NOW_PACKAGES])
    later[:0] = [dict(x, note="serious, after the Do-now ones") for x in serious_small[PLAN_NOW_PACKAGES:]]
    # code fixes first within each group, then packages
    later.sort(key=lambda x: 0 if x["kind"] == "fix" else 1)
    return {"now": now, "later": later, "wait": wait, "wait_groups": wait_groups}


def render_deep_cards_html(data, fixes_url, packages_url, fitness_url="", fitness_verdict=None):
    """The deep report's three cards (3 Nov 2026, Moses: a summary of each, with the details on a page of its own):
    Security fixes, Packages and Code fitness. Red, amber and grey; no violet. '' for a report with nothing to show."""
    fixes = [f for f in (data.get("top_fixes") or []) if isinstance(f, dict) and f.get("title")]
    n_crit = sum(1 for f in fixes if (f.get("severity") or "").lower() == "critical")
    n_other = len(fixes) - n_crit
    plan = build_plan(data, fixes_url, packages_url) or {"now": [], "later": [], "wait": []}
    pk = lambda key: sum(1 for x in plan.get(key, []) if x["kind"] == "package")
    groups = (data.get("dependency_fixes") or {}).get("groups") or []
    osv = data.get("osv_scan") or {}

    def card(href, icon, title, big, big_fg, line, link_text):
        return (f'<a href="{_esc(href)}" class="dcard" style="display:flex;flex-direction:column;gap:6px;background:#fff;'
                'border:.5px solid #e5e5f0;border-radius:12px;padding:12px 14px;text-decoration:none;color:#1a1917">'
                f'<div style="display:flex;align-items:center;gap:8px;font-weight:700"><span aria-hidden="true">{icon}</span>{_esc(title)}</div>'
                f'<div style="font-size:21px;font-weight:800;color:{big_fg};line-height:1.2">{_esc(big)}</div>'
                f'<div style="font-size:13px;color:#5F5E5A;line-height:1.5">{_esc(line)}</div>'
                f'<div style="font-size:13px;font-weight:600;margin-top:auto">{_esc(link_text)} &rarr;</div></a>')

    if n_crit:
        sec_big, sec_fg = (f"{n_crit} critical" + (f" · {n_other} more" if n_other else "")), "#791F1F"
    elif n_other:
        sec_big, sec_fg = f"{_plural(n_other, 'fix', 'fixes')} to look at", "#633806"
    else:
        sec_big, sec_fg = "Nothing to fix", "#27500A"
    cards = [card(fixes_url, "&#128737;", "Security fixes", sec_big, sec_fg,
                  "What we found in each area of your app, with a fix prompt for each.", "See fixes")]
    if groups:
        now_n, later_n, wait_n = pk("now"), pk("later"), pk("wait")
        cards.append(card(packages_url, "&#128230;", "Packages", f"{len(groups)} to update",
                          "#791F1F" if now_n else "#633806",
                          f"{now_n} urgent · {later_n} worth doing later · {wait_n} can wait, sorted high to low.", "See packages"))
    elif osv.get("packages_checked"):
        cards.append(card(packages_url, "&#128230;", "Packages", "None vulnerable", "#27500A",
                          "Every package Verilay could read was checked against a public database of known problems.",
                          "See packages"))
    if fitness_url and fitness_verdict:
        fg = {"ok": "#27500A", "warn": "#633806", "bad": "#791F1F"}.get(fitness_verdict.get("tone"), "#444441")
        cards.append(card(fitness_url, "&#128208;", "Code fitness", fitness_verdict.get("label", ""), fg,
                          fitness_verdict.get("why", ""), "See code fitness"))
    return ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:1rem" '
            'id="deep-cards">' + "".join(cards) + '</div>')


def _ordered_groups(groups):
    """The package groups in the order render_fixes_html shows them (runtime first, then build tools), so the plan's
    links (#dpgN) point at the right entry."""
    return [g for g in groups if not g.get("is_dev")] + [g for g in groups if g.get("is_dev")]


def render_plan_html(data, fixes_url="", packages_url="", folded=False):
    """The "Your plan" card for the top of a deep report. '' when there is nothing to sort. `folded`: the deep report's
    summary page shows the counts and the first thing to do, with the whole plan in a fold (3 Nov 2026)."""
    plan = build_plan(data, fixes_url, packages_url)
    if not plan:
        return ""
    fixes = [f for f in (data.get("top_fixes") or []) if isinstance(f, dict)]
    n_crit = sum(1 for f in fixes if (f.get("severity") or "").lower() == "critical")
    n_warn = len(fixes) - n_crit
    n_pkg = len((data.get("dependency_fixes") or {}).get("groups") or [])
    # Counts the FIX PROMPTS, so it never says "warnings" (the score box counts every warning in the six areas; 3 Nov 2026)
    head_bits = [b for b in (_plural(n_crit, "critical fix", "critical fixes") if n_crit else "",
                             _plural(n_warn, "other fix", "other fixes") if n_warn else "",
                             _plural(n_pkg, "package update", "package updates") if n_pkg else "") if b]

    def row(x, color):
        note = (f'<span style="display:block;font-size:11px;color:{color};margin-top:1px">{_esc(x["note"])}</span>'
                if x.get("note") else "")
        return (f'<a href="{_esc(x["href"])}" style="display:block;background:#fff;border-radius:8px;padding:7px 10px;'
                f'font-size:13px;text-decoration:none;color:inherit">{_esc(x["title"])}{note}</a>')

    def box(key, title, sub, border, bg, fg, sub_fg, items, limit):
        if not items:
            return ""
        shown = items[:limit]
        rest = len(items) - len(shown)
        more = (f'<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px;color:{sub_fg}">'
                f'Show {rest} more</summary><div style="display:grid;gap:5px;margin-top:6px">'
                + "".join(row(x, sub_fg) for x in items[limit:]) + '</div></details>') if rest > 0 else ""
        return (f'<div id="plan-{key}" style="border:{border};background:{bg};border-radius:12px;padding:11px 13px;margin-bottom:9px;color:{fg}">'
                f'<div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;margin-bottom:7px"><span style="font-weight:700">{title}</span>'
                f'<span style="font-size:12px;color:{sub_fg}">{len(items)} &middot; {sub}</span></div>'
                f'<div style="display:grid;gap:5px">' + "".join(row(x, sub_fg) for x in shown) + f'</div>{more}</div>')

    wg = plan["wait_groups"]
    chips = []
    if wg["tools"]:
        chips.append(f'Build and test tools &middot; {wg["tools"]}')
    for folder, n in sorted(wg["side"].items()):
        chips.append(f'Side folder <code style="font-size:11px">{_esc(folder)}/</code> (not your app) &middot; {n}')
    if wg["low"]:
        chips.append(f'Low risk &middot; {wg["low"]}')
    wait_html = ""
    if plan["wait"]:
        wait_html = ('<div id="plan-wait" style="border:.5px solid #e5e3dc;background:#F6F5F2;border-radius:12px;padding:11px 13px;margin-bottom:9px;color:#2C2C2A">'
                     f'<div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;margin-bottom:5px"><span style="font-weight:700">Can wait</span>'
                     f'<span style="font-size:12px;color:#5F5E5A">{len(plan["wait"])} &middot; housekeeping, not risk</span></div>'
                     '<div style="font-size:13px;color:#5F5E5A;line-height:1.55;margin-bottom:7px">Packages that never reach your users. '
                     'Leave these unless you&rsquo;re already updating.</div>'
                     '<div style="display:flex;flex-wrap:wrap;gap:6px;font-size:12px">'
                     + "".join(f'<span style="background:#fff;border:.5px solid #e5e3dc;border-radius:20px;padding:3px 10px">{c}</span>' for c in chips)
                     + '</div><details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px;color:#5F5E5A">Show all</summary>'
                     '<div style="display:grid;gap:5px;margin-top:6px">' + "".join(row(x, "#5F5E5A") for x in plan["wait"]) + '</div></details></div>')

    boxes = (box("now", "Do now", "start here", "2px solid #A32D2D", "#FCEBEB", "#501313", "#A32D2D", plan["now"], 6)
             + box("later", "Worth doing later", "one at a time, when you have time", ".5px solid #EF9F27", "#FAEEDA",
                   "#412402", "#854F0B", plan["later"], 5)
             + wait_html)
    note = ('<div style="font-size:12px;color:#6b6966;line-height:1.55;border-top:.5px solid #e5e3dc;padding-top:9px;margin-top:4px">'
            'Every fix prompt asks your AI builder what the change could break first. Not sure whether a package reaches '
            'your users? Verilay keeps it out of &ldquo;Can wait&rdquo;. Your grade doesn&rsquo;t change: this only sorts the list.</div>')
    if folded:
        pill = lambda bg, fg, border, label, n: (f'<span style="background:{bg};color:{fg};border:{border};border-radius:20px;'
                                                 f'padding:4px 12px;font-size:13px;font-weight:600">{label} &middot; {n}</span>')
        first = plan["now"][0] if plan["now"] else (plan["later"][0] if plan["later"] else None)
        start = (f'<a href="{_esc(first["href"])}" style="display:block;margin-top:9px;font-size:14px;color:#1a1917;text-decoration:none">'
                 f'<span style="color:#A32D2D;font-weight:700">&rarr; Start here:</span> {_esc(first["title"])}</a>') if first else ""
        return ('<div class="card" id="your-plan"><div style="font-weight:700;font-size:16px;margin-bottom:8px">Your plan</div>'
                '<div style="display:flex;gap:8px;flex-wrap:wrap">'
                + pill("#FCEBEB", "#791F1F", "1px solid #A32D2D", "Do now", len(plan["now"]))
                + pill("#FAEEDA", "#633806", "0", "Later", len(plan["later"]))
                + pill("#F6F5F2", "#5F5E5A", "0", "Can wait", len(plan["wait"])) + '</div>' + start
                + '<details style="margin-top:10px"><summary style="cursor:pointer;font-size:13px;color:#5F5E5A">See the whole plan</summary>'
                  '<div style="margin-top:9px">' + boxes + note + '</div></details></div>')
    return ('<div class="st">Your plan</div><div class="card" id="your-plan">'
            f'<div style="font-size:12px;color:#6b6966;margin-bottom:3px">{_esc(" · ".join(head_bits))}, sorted for you</div>'
            '<div style="font-size:13px;color:#444;margin-bottom:11px">Start at the top. One fix at a time, then re-scan. '
            + ('Most of this list can safely wait.' if len(plan["wait"]) > len(plan["now"]) + len(plan["later"]) else
               'Fix prompts for each one are further down.') + '</div>'
            + box("now", "Do now", "start here", "2px solid #A32D2D", "#FCEBEB", "#501313", "#A32D2D", plan["now"], 6)
            + box("later", "Worth doing later", "one at a time, when you have time", ".5px solid #EF9F27", "#FAEEDA",
                  "#412402", "#854F0B", plan["later"], 5)
            + wait_html
            + '<div style="font-size:12px;color:#6b6966;line-height:1.55;border-top:.5px solid #e5e3dc;padding-top:9px;margin-top:4px">'
            'Every fix prompt asks your AI builder what the change could break first. Not sure whether a package reaches '
            'your users? Verilay keeps it out of &ldquo;Can wait&rdquo;. Your grade doesn&rsquo;t change: this only sorts the list.</div>'
            '</div>')


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


def render_fixes_html(data, part="all"):
    """The saved report's 'Fix these first' section. Returns '' when there is nothing to fix. `part`: "all", "code"
    (the fix prompts for findings in the app's own code) or "packages" (the package updates): the deep report's own
    pages show one each (3 Nov 2026)."""
    fixes = data.get("top_fixes") or [] if part in ("all", "code") else []
    dep = data.get("dependency_fixes") or {}
    groups = (dep.get("groups") or []) if part in ("all", "packages") else []
    if not fixes and not groups:
        return ""

    title = {"code": "Fix prompts", "packages": "Packages to update"}.get(part, "Fix these first")
    parts = [f'<div class="st">{title}</div><div class="card">',
             '<div style="font-size:13px;color:#555;margin-bottom:.5rem">Copy a prompt, paste it into your AI '
             'builder (Lovable, Replit, Bolt, Cursor&hellip;), then re-run Verilay to check it worked. '
             'Treat each one as something to verify, not an order: your AI builder knows your code.</div>']

    ai_html = ""
    for i, f in enumerate(fixes):
        prompt = f.get("lovable_prompt") or f.get("general_prompt") or fallback_prompt(f)
        sev = (f.get("severity") or "warning").lower()
        tag = _fix_label(f)
        tag_html = (f'<span style="display:block;font-size:11px;font-weight:400;color:#6b6966;margin-top:2px">'
                    f'{_esc(tag)}</span>') if tag else ""
        ai_html += (f'<details class="fix" id="{_fix_anchor(f, i)}"><summary style="cursor:pointer;font-weight:600">{_esc(f.get("priority", ""))}. '
                    f'{_esc(f.get("title", ""))}{_pill(sev, sev)}{tag_html}</summary>'
                    f'<div style="font-size:13px;color:#555;margin:.5rem 0 .35rem">{_esc(f.get("why_it_matters", ""))}</div>'
                    f'<div style="font-size:13px;color:#444"><strong>How:</strong> {_esc(f.get("how_to_fix", ""))}</div>'
                    f'<div style="font-size:12px;color:#888">Effort: {_esc(f.get("estimated_effort", ""))}</div>'
                    f'{_prompt_block(f"fp{i}", prompt) if prompt else ""}{_selfcheck.render_for_fix(f)}</details>')

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
        dep_html += _selfcheck.render(["old_packages"])
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
