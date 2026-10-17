"""verilay_fixtags.py - says which part of the app, and which technology, each "Fix these first" prompt is about.

Each fix gets two optional labels:
  area  one of the six layers Verilay reports on: Auth, Config, Database, API, Frontend, Libraries
  tech  up to three names taken from the tech stack Verilay detected for THIS app (e.g. Sequelize, Angular)

How it works, and why it is built this way:
  * It is a separate, small AI step that runs AFTER the fixes have been written. The big fix-writing prompt is not
    touched, so adding labels can never cut off or change the fixes themselves.
  * The AI may only choose from closed lists (the six areas, the detected stack names). Everything it returns is
    checked against those lists and anything not on them is thrown away, so a label can never be invented.
  * If the step fails for any reason, the fixes are returned exactly as they were, with no labels. Nothing breaks.
  * Reports saved before this existed simply have no labels and show none.
"""
import re

AREAS = ("Auth", "Config", "Database", "API", "Frontend", "Libraries")
MAX_TECH = 3
MAX_FIXES = 8
_MAX_STACK = 30


def clean_stack(raw):
    """Stack names from whatever the browser sent: a list of strings or of {name: ...}. Short, de-duplicated, in order."""
    out, seen = [], set()
    for item in (raw if isinstance(raw, list) else [])[:_MAX_STACK]:
        name = item.get("name") if isinstance(item, dict) else item
        if not isinstance(name, str):
            continue
        name = re.sub(r"\s+", " ", name).strip()[:60]
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def build_prompt(fixes, stack_names, findings_summary=""):
    lines = []
    for i, f in enumerate(fixes[:MAX_FIXES], 1):
        title = re.sub(r"\s+", " ", str(f.get("title") or ""))[:140]
        why = re.sub(r"\s+", " ", str(f.get("why_it_matters") or ""))[:240]
        lines.append(f"{i}. {title} - {why}")
    stack = ", ".join(stack_names) if stack_names else "(none detected)"
    listed = re.sub(r"[ \t]+", " ", str(findings_summary or "")).strip()[:1500]
    listed_block = (
        "How the report listed its findings, layer by layer:\n" + listed + "\n"
        "If a fix is the same problem as one listed there, its AREA is the layer it is listed under. Never choose a "
        "layer the report shows as having no issues.\n\n"
    ) if listed else ""
    return (
        "You label security fixes in a report for a non-developer. For each numbered fix below give two labels.\n"
        "AREA: exactly one of " + ", ".join(AREAS) + " - the part of the app the fix is about "
        "(Auth = login and sessions, Config = settings and secrets, Database = data storage and queries, "
        "API = server routes and endpoints, Frontend = what runs in the browser, Libraries = installed packages).\n"
        "TECH: zero to three names copied EXACTLY from the detected stack below that the fix is directly about. "
        "Choose a name only if the fix clearly names or depends on that technology. If none fits, write none. "
        "Never write a name that is not in the list.\n\n"
        f"Detected stack: {stack}\n\n" + listed_block + "Fixes:\n" + "\n".join(lines) + "\n\n"
        "Respond ONLY with lines in this exact form, no other text:\n"
        "FIX_1_AREA: <one area>\nFIX_1_TECH: <names separated by commas, or none>\n"
        "FIX_2_AREA: ...\nFIX_2_TECH: ...\n(and so on for every fix)"
    )


def parse(text, count, stack_names):
    """-> list of {"area": str|None, "tech": [str]}, one per fix, every value validated against the closed lists."""
    keyed = {}
    for line in str(text or "").splitlines():
        m = re.match(r"\s*FIX[_ ]?(\d+)[_ ]?(AREA|TECH)\s*:\s*(.*)$", line, re.I)
        if m:
            keyed[(int(m.group(1)), m.group(2).upper())] = m.group(3).strip()
    areas = {a.lower(): a for a in AREAS}
    stack = {s.lower(): s for s in stack_names}
    out = []
    for i in range(1, min(count, MAX_FIXES) + 1):
        area = areas.get(re.sub(r"[^a-z]", "", keyed.get((i, "AREA"), "").lower()))
        tech, seen = [], set()
        for part in re.split(r"[,;/]", keyed.get((i, "TECH"), "")):
            real = stack.get(re.sub(r"\s+", " ", part).strip().strip(".").lower())
            if real and real.lower() not in seen:
                seen.add(real.lower())
                tech.append(real)
        out.append({"area": area, "tech": tech[:MAX_TECH]})
    return out


def tag_fixes(fixes, stack_names, call, findings_summary=""):
    """Adds "area" and "tech" to each fix (in place) and returns the list. `call(prompt, max_tokens)` is the AI helper.
    `findings_summary` is the layer-by-layer text the fixes were written from; it keeps each area consistent with the
    report's own layer list (see align_areas). Never raises: on any failure the fixes are returned unchanged."""
    try:
        fixes = fixes if isinstance(fixes, list) else []
        real = [f for f in fixes if isinstance(f, dict)]
        if not real:
            return fixes
        stack = clean_stack(stack_names)
        tags = parse(call(build_prompt(real, stack, findings_summary), 400), len(real), stack)
        for f, t in zip(real, tags):
            if t["area"]:
                f["area"] = t["area"]
            if t["tech"]:
                f["tech"] = t["tech"]
        align_areas(real, findings_summary)
    except Exception as e:  # labels are a nicety; they must never be able to break a scan
        print(f"[fixtags] skipped: {type(e).__name__}", flush=True)
    return fixes


def label(fix):
    """'Database · Sequelize, SQLite3' (or just one part, or '') from a fix dict. Re-validates what is stored."""
    if not isinstance(fix, dict):
        return ""
    area = fix.get("area") if fix.get("area") in AREAS else ""
    tech = [t for t in (fix.get("tech") if isinstance(fix.get("tech"), list) else []) if isinstance(t, str)][:MAX_TECH]
    return " · ".join(x for x in (area, ", ".join(tech)) if x)


def anchor(fix, index):
    """The page anchor of a fix: fix-<its priority number>, or fix-<position> if it has none. Shared by the fix list and
    by anything that links to a fix, so the two can never disagree."""
    try:
        n = int(fix.get("priority"))
    except (TypeError, ValueError, AttributeError):
        n = index + 1
    return f"fix-{n}"


def dependency_fix_anchor(fixes):
    """(anchor, title) of the first fix that is about dependencies, or None. Used by the dependency card to point at it."""
    for i, f in enumerate(fixes if isinstance(fixes, list) else []):
        if isinstance(f, dict) and re.search(r"dependenc|vulnerable (package|librar)|outdated (package|librar)", str(f.get("title") or ""), re.I):
            return anchor(f, i), str(f.get("title") or "")
    return None


# ── Keeping a fix's area consistent with the report's own layer list ───────────────────────────────────────────
# The layer analysis files each problem under ONE layer (e.g. a JWT bypass under API, with Auth shown as passing).
# A label that says "Auth" for that same fix would contradict the page. So a fix may only be labelled with a layer
# the report itself shows a problem in, and when a fix clearly matches a listed finding, that finding's layer wins.

_STOP = frozenset("the and for with via from into that this not are can all any your you its has have how why use using "
                  "across without over per only but out off was were been being more most some such than then them "
                  "these those their there what when where which while who whom will would should could may might "
                  "also very just like each every both either neither other another".split())
_NO_PROBLEM = re.compile(r"^\s*(no issues found|no known dependency vulnerabilit)", re.I)
_LAYER_LINE = re.compile(r"^\s*-\s*(Auth|Config|Database|API|Frontend|Libraries)\s*(?:\[[^\]]*\])?\s*:\s*(.*)$", re.I)


def _stems(text):
    """The first five letters of each meaningful word, with a plural 's' dropped (user / users match)."""
    out = set()
    for w in re.findall(r"[a-z0-9]{3,}", str(text or "").lower()):
        if w in _STOP:
            continue
        if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        out.add(w[:5])
    return out


def problem_layers(findings_summary):
    """{layer name: its findings text} for layers the summary lists a PROBLEM in (not 'no issues found')."""
    out = {}
    names = {a.lower(): a for a in AREAS}
    for line in str(findings_summary or "").splitlines():
        m = _LAYER_LINE.match(line)
        if not m:
            continue
        # The deep scan adds an instruction after the Libraries count ("Verilay lists these and writes the package-update
        # fixes itself, so do NOT write fixes for dependencies..."). That is a note to the AI, not a finding: leave it out.
        body = re.split(r"\bVerilay lists these\b", m.group(2))[0].strip()
        if body and not _NO_PROBLEM.match(body):
            layer = names[m.group(1).lower()]
            out[layer] = (out.get(layer, "") + " " + body).strip()
    return out


def align_areas(fixes, findings_summary):
    """Makes each fix's area agree with the report's layer list. In place; never raises. With no usable summary it
    changes nothing."""
    try:
        layers = problem_layers(findings_summary)
        if not layers:
            return fixes
        layer_stems = {name: _stems(text) for name, text in layers.items()}
        for f in fixes:
            if not isinstance(f, dict):
                continue
            title = _stems(f.get("title"))
            why = _stems(f.get("why_it_matters"))
            if not title:
                continue
            scored = []
            for name, st in layer_stems.items():
                shared = len(title & st)
                scored.append((shared / len(title), len(why & st), shared, name))
            scored.sort(reverse=True)
            best_score, _w, best_shared, best = scored[0]
            ai = f.get("area")
            ai_score = next((s for s, _w2, _sh, n in scored if n == ai), 0.0)
            tie = len(scored) > 1 and scored[1][0] == best_score and scored[1][1] == scored[0][1]
            if best_shared >= 2 and best_score >= 0.5 and not tie and (ai not in layers or best_score > ai_score + 0.2):
                f["area"] = best            # the report files this problem under that layer
            elif ai in layers:
                pass                         # the AI's choice is a layer the report shows a problem in: keep it
            elif best_shared >= 1 and best_score >= 0.25 and not tie:
                f["area"] = best            # the AI chose a layer with no problem listed: use the closest one that has
            else:
                f.pop("area", None)          # no honest area to show: show none rather than a contradiction
    except Exception as e:
        print(f"[fixtags] align skipped: {type(e).__name__}", flush=True)
    return fixes
