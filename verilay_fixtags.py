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


def build_prompt(fixes, stack_names):
    lines = []
    for i, f in enumerate(fixes[:MAX_FIXES], 1):
        title = re.sub(r"\s+", " ", str(f.get("title") or ""))[:140]
        why = re.sub(r"\s+", " ", str(f.get("why_it_matters") or ""))[:240]
        lines.append(f"{i}. {title} - {why}")
    stack = ", ".join(stack_names) if stack_names else "(none detected)"
    return (
        "You label security fixes in a report for a non-developer. For each numbered fix below give two labels.\n"
        "AREA: exactly one of " + ", ".join(AREAS) + " - the part of the app the fix is about "
        "(Auth = login and sessions, Config = settings and secrets, Database = data storage and queries, "
        "API = server routes and endpoints, Frontend = what runs in the browser, Libraries = installed packages).\n"
        "TECH: zero to three names copied EXACTLY from the detected stack below that the fix is directly about. "
        "Choose a name only if the fix clearly names or depends on that technology. If none fits, write none. "
        "Never write a name that is not in the list.\n\n"
        f"Detected stack: {stack}\n\nFixes:\n" + "\n".join(lines) + "\n\n"
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


def tag_fixes(fixes, stack_names, call):
    """Adds "area" and "tech" to each fix (in place) and returns the list. `call(prompt, max_tokens)` is the AI helper.
    Never raises: on any failure the fixes are returned unchanged."""
    try:
        fixes = fixes if isinstance(fixes, list) else []
        real = [f for f in fixes if isinstance(f, dict)]
        if not real:
            return fixes
        stack = clean_stack(stack_names)
        tags = parse(call(build_prompt(real, stack), 400), len(real), stack)
        for f, t in zip(real, tags):
            if t["area"]:
                f["area"] = t["area"]
            if t["tech"]:
                f["tech"] = t["tech"]
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
