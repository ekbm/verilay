"""Compare a scan with an earlier scan of the same app: what is no longer found, what is still there, what is new.

No AI. Works on two saved reports (the dicts stored in Supabase). Honest by design:
- the wording is "no longer found", never "fixed": a finding can disappear because the code changed, because the
  scan read different files, or because the AI worded it differently;
- areas that were not checked in either scan (an unreadable AI answer, an unfinished check, or the old filler text
  that the parser used to write when no answer came back) are left out and named, never counted as clean;
- if the two scans read clearly different files, the result says so;
- a scan that did not finish, or a live-address scan (no code read), is not compared at all.
"""
import re

SEVERITIES = ("critical", "warning")
# Words that carry no meaning when matching two AI-written finding titles.
_STOP = set("a an and are as at be by for from in into is it its of on or the this that to was were with without "
            "your you no not any all".split())
SIMILAR = 0.5          # word overlap that makes two titles in the same area "the same finding"
SIMILAR_SAME_FILE = 0.3
SAME_FILES = 0.6       # overlap of the file lists below which the scans are "reading different files"


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in _STOP and len(w) > 1}


def _overlap(a, b):
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def is_filler_layer(layer):
    """The text the old parser wrote when no AI answer came back: '<Name> layer analysis.' and only 'No issues found'.
    Reports saved before 25 Oct 2026 can hold it; it is not a result."""
    ex = (layer or {}).get("expert") or {}
    findings = ex.get("findings") or []
    return (ex.get("summary") == f"{(layer or {}).get('name', '')} layer analysis."
            and all((f.get("title") or "") == "No issues found" for f in findings))


def unchecked_areas(report):
    """Areas of a report that hold no real result."""
    names = set(str(x) for x in (report.get("analysis_incomplete") or []))
    names |= set(str(x) for x in (report.get("layers_not_checked") or []))
    for layer in report.get("layers") or []:
        if layer.get("status") == "not_checked" or is_filler_layer(layer):
            names.add(layer.get("name", ""))
    names.discard("")
    return names


def _findings(report, skip):
    out = []
    for layer in report.get("layers") or []:
        area = layer.get("name", "")
        if area in skip:
            continue
        for f in (layer.get("expert") or {}).get("findings") or []:
            sev = (f.get("severity") or "").lower()
            title = (f.get("title") or "").strip()
            if sev in SEVERITIES and title:
                out.append({"area": area, "title": title[:200], "severity": sev, "file": (f.get("file") or "")[:200]})
    return out


def _match(old, new):
    """Pair each old finding with at most one new finding in the same area. Returns (pairs, unmatched_old, unmatched_new)."""
    cands = []
    for i, o in enumerate(old):
        for j, n in enumerate(new):
            if o["area"] != n["area"]:
                continue
            score = 1.0 if _words(o["title"]) == _words(n["title"]) and _words(o["title"]) else _overlap(o["title"], n["title"])
            same_file = o["file"] and o["file"] == n["file"]
            if score >= SIMILAR or (same_file and score >= SIMILAR_SAME_FILE):
                cands.append((score + (0.01 if same_file else 0), i, j))
    cands.sort(reverse=True)
    used_o, used_n, pairs = set(), set(), []
    for _, i, j in cands:
        if i in used_o or j in used_n:
            continue
        used_o.add(i); used_n.add(j); pairs.append((old[i], new[j]))
    return (pairs, [o for i, o in enumerate(old) if i not in used_o], [n for j, n in enumerate(new) if j not in used_n])


def _count(report, key, field):
    try:
        return int(((report.get(key) or {}).get(field)) or 0)
    except (TypeError, ValueError):
        return 0


def _files(report):
    f = report.get("files_analysed")
    return set(f) if isinstance(f, list) else set()


def compare(old, new):
    """The comparison as a plain dict (safe to store and to show). `comparable` is False with a `reason` when the two
    reports cannot honestly be compared."""
    old, new = old or {}, new or {}
    for rep, which in ((new, "this scan"), (old, "the earlier scan")):
        if rep.get("preview_only") or not rep.get("layers"):
            return {"comparable": False, "reason": f"{which.capitalize()} did not read your code (for example a "
                    "live-address check), so there is nothing to compare."}
    layer_names = {l.get("name", "") for l in new.get("layers") or []}
    new_skip, old_skip = unchecked_areas(new), unchecked_areas(old)
    if layer_names and layer_names <= new_skip:
        return {"comparable": False, "reason": "This scan did not finish checking your app, so it cannot be compared. "
                "Run the analysis again."}
    skip = new_skip | old_skip
    pairs, gone, added = _match(_findings(old, skip), _findings(new, skip))
    still = [dict(n, before=o["severity"]) for o, n in pairs]

    checks = []
    for label, key, field in (("Exposed keys", "secret_scan", "critical"),
                              ("Packages with known problems", "osv_scan", "vulnerabilities_found")):
        b, a = _count(old, key, field), _count(new, key, field)
        if b or a:
            checks.append({"label": label, "before": b, "after": a})

    fo, fn = _files(old), _files(new)
    same_files, files_note = True, ""
    if fo and fn:
        common = len(fo & fn)
        if common / len(fo | fn) < SAME_FILES:
            same_files = False
            files_note = (f"The two scans read different files ({common} of {len(fo | fn)} in common), so some "
                          "differences may come from that rather than from changes you made.")

    def grade(r):
        return None if r.get("analysis_incomplete") else (r.get("health") or {}).get("score")

    return {
        "comparable": True,
        "grade_before": grade(old),
        "grade_after": grade(new),
        "no_longer_found": gone,
        "still_found": still,
        "new_found": added,
        "checks": checks,
        "not_compared": sorted(skip),
        "same_files": same_files,
        "files_note": files_note,
    }


def _when(ts):
    """'24 Oct 2026, 18:05 UTC' from an ISO timestamp; the text as it is when it is not one."""
    import datetime as _dt
    try:
        d = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if d.tzinfo is not None:
            d = d.astimezone(_dt.timezone.utc)
        return d.strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        return str(ts or "")


_GROUPS = (("no_longer_found", "No longer found", "#1D9E75", "#EAF3DE"),
           ("still_found", "Still there", "#92400E", "#FEF3C7"),
           ("new_found", "New in this scan", "#A32D2D", "#FCEBEB"))
_SEV = {"critical": ("#A32D2D", "#FCEBEB"), "warning": ("#92400E", "#FEF3C7")}
_GRADE = {"A": "#1D9E75", "B": "#4A90D9", "C": "#EF9F27", "D": "#E24B4A", "F": "#A32D2D"}


def render_html(result):
    """The comparison card for the saved report page (no JavaScript; escapes everything itself). '' when none."""
    import html as _h
    if not isinstance(result, dict) or not result:
        return ""
    e = _h.escape
    when = _when(result.get("previous_at"))
    head = (f'<div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.06em;text-transform:uppercase;'
            f'margin-bottom:.35rem">Compared with your earlier scan</div>'
            f'<div style="font-size:13px;color:#555;margin-bottom:.5rem">{e(result.get("previous_repo") or "Earlier scan")}'
            f'{(" &middot; " + e(when)) if when else ""}</div>')
    if not result.get("comparable"):
        return (f'<div class="card" id="comparison">{head}<div style="font-size:14px;color:#444">'
                f'{e(result.get("reason") or "These scans could not be compared.")}</div></div>')
    # Same look as compareResultHTML in app.js: number tiles, grade badges, one row per issue (plain title, grey
    # "where" line, a small severity tag) and the fine print in one quiet box. Colour sits only on tags and tiles.
    gb, ga = result.get("grade_before"), result.get("grade_after")

    def badge(g):
        return (f'<span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;'
                f'border-radius:50%;font-size:14px;font-weight:700;color:#fff;background:{_GRADE.get(g, "#999")}">'
                f'{e(g or "–")}</span>')

    grade = (f'<div style="display:flex;align-items:center;gap:8px;font-size:13px;color:#6b6966;margin-bottom:.75rem">'
             f'Grade {badge(gb)}<span style="font-size:16px">&rarr;</span>{badge(ga)}</div>') if (gb or ga) else ""
    tiles = "".join(
        f'<div style="background:{bg};border-radius:8px;padding:.6rem .5rem;text-align:center">'
        f'<div style="font-size:22px;font-weight:700;color:{fg};line-height:1.1">{len(result.get(key) or [])}</div>'
        f'<div style="font-size:12px;color:#444;margin-top:2px">{label}</div></div>'
        for key, label, fg, bg in _GROUPS)
    section = ('<div style="font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#6b6966;'
               'margin:1rem 0 .15rem">{}</div>')
    groups = ""
    for key, label, _fg, _bg in _GROUPS:
        rows = result.get(key) or []
        if not rows:
            continue
        groups += section.format(f"{label} &middot; {len(rows)}")
        for r in rows:
            sev = r.get("severity", "")
            sfg, sbg = _SEV.get(sev, ("#444", "#eee"))
            where = " &middot; ".join(e(x) for x in (r.get("area"), r.get("file")) if x)
            if key == "still_found" and r.get("before") and r.get("before") != sev:
                where += f' &middot; was {e(r["before"])}'
            groups += (f'<div style="display:flex;align-items:flex-start;gap:10px;padding:.55rem 0;border-top:0.5px solid #e5e3dc">'
                       f'<div style="flex:1;min-width:0"><div style="font-size:14px;color:#1a1917;line-height:1.4">'
                       f'{e(r.get("title", ""))}</div><div style="font-size:12px;color:#6b6966;margin-top:2px">{where}</div></div>'
                       f'<span style="flex-shrink:0;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;'
                       f'color:{sfg};background:{sbg}">{e(sev)}</span></div>')
    if result.get("checks"):
        groups += section.format("Automatic checks") + "".join(
            f'<div style="display:flex;justify-content:space-between;padding:.45rem 0;border-top:0.5px solid #e5e3dc;'
            f'font-size:14px"><span>{e(c["label"])}</span><span style="color:#6b6966">{int(c["before"])} &rarr; '
            f'<strong style="color:#1a1917">{int(c["after"])}</strong></span></div>' for c in result["checks"])
    notes = []
    if result.get("files_note"):
        notes.append(e(result["files_note"]))
    if result.get("not_compared"):
        notes.append("Not compared, because one of the scans did not check them: "
                     + e(", ".join(result["not_compared"])) + ".")
    notes.append("&ldquo;No longer found&rdquo; means this scan did not report it. The AI can word the same issue "
                 "differently between scans, so check the list before treating anything as fixed.")
    note_html = ('<div style="background:#F6F5F2;border-radius:8px;padding:.6rem .8rem;margin-top:1rem;font-size:12px;'
                 'color:#6b6966;line-height:1.55">' + "".join(f'<div style="margin:.15rem 0">{n}</div>' for n in notes) + '</div>')
    return (f'<div class="card" id="comparison">{head}{grade}'
            f'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">{tiles}</div>{groups}{note_html}</div>')


def headline(result):
    """One plain line, e.g. '2 issues no longer found, 1 still there, 0 new.'"""
    if not result or not result.get("comparable"):
        return (result or {}).get("reason") or "These scans could not be compared."
    def n(k, one, many):
        c = len(result.get(k) or [])
        return f"{c} {one if c == 1 else many}"
    return (n("no_longer_found", "issue no longer found", "issues no longer found") + ", "
            + n("still_found", "still there", "still there") + ", " + n("new_found", "new", "new") + ".")
