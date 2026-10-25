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


_GRADE_ORDER = "ABCDF"


def improved(result):
    """True when a comparison shows real progress: a better grade, or at least one issue no longer found with the
    grade no worse. Used to decide whether to ask "what did you change?"."""
    if not isinstance(result, dict) or not result.get("comparable"):
        return False
    gb, ga = result.get("grade_before"), result.get("grade_after")
    if isinstance(gb, str) and isinstance(ga, str) and len(gb) == len(ga) == 1 and gb in _GRADE_ORDER and ga in _GRADE_ORDER:
        if _GRADE_ORDER.index(ga) < _GRADE_ORDER.index(gb):
            return True
        if _GRADE_ORDER.index(ga) > _GRADE_ORDER.index(gb):
            return False
    return bool(result.get("no_longer_found"))


def headline(result):
    """One plain line, e.g. '2 issues no longer found, 1 still there, 0 new.'"""
    if not result or not result.get("comparable"):
        return (result or {}).get("reason") or "These scans could not be compared."
    def n(k, one, many):
        c = len(result.get(k) or [])
        return f"{c} {one if c == 1 else many}"
    return (n("no_longer_found", "issue no longer found", "issues no longer found") + ", "
            + n("still_found", "still there", "still there") + ", " + n("new_found", "new", "new") + ".")


# ── The compare page (/compare/<id>, 25 Oct 2026) ──────────────────────────────────────────────────────────────────
# Moses approved a page of its own instead of a box on the report: one honest headline first, then the details. Three
# situations get their own wording: the earlier scan was incomplete (its grade was not a full grade), Free vs Pro
# (Pro read more, so it found more: not new problems), and a normal rescan.
_AREAS = 6


def scan_meta(report, at=""):
    """What one scan was, stored with the comparison: kind (free/pro/deep), grade, areas checked, files read, fix
    prompts and when. Small and safe to show."""
    report = report or {}
    layers = report.get("layers") or []
    total = len(layers) or _AREAS
    checked = max(0, total - len(unchecked_areas(report) & {l.get("name", "") for l in layers})) if layers else 0
    kind = "deep" if report.get("is_deep_scan") else ("pro" if report.get("scan_tier") == "pro" else "free")
    files = report.get("files_read")
    if not isinstance(files, int):
        files = len(report.get("files_analysed") or []) or None
    return {"kind": kind, "grade": None if report.get("analysis_incomplete") else (report.get("health") or {}).get("score"),
            "areas_checked": checked, "areas_total": total, "files": files,
            "prompts": len(report.get("top_fixes") or []), "at": str(at or "")[:32]}


def situation(result):
    """'not_comparable', 'incomplete' (the earlier scan checked too little to compare fairly), 'free_vs_pro' or 'rescan'."""
    if not isinstance(result, dict) or not result.get("comparable"):
        return "not_comparable"
    b, a = result.get("before") or {}, result.get("after") or {}
    nc = len(result.get("not_compared") or [])
    if nc >= 3 or (b.get("areas_checked") is not None and b.get("areas_checked", 6) <= 3
                   and b.get("areas_checked", 6) < a.get("areas_checked", 6)):
        return "incomplete"
    if b.get("kind") == "free" and a.get("kind") in ("pro", "deep"):
        return "free_vs_pro"
    return "rescan"


_KIND = {"free": ("Free scan", "#F1EFE8", "#888780", "#444441"),
         "pro": ("Verilay Pro", "#EEEDFE", "#534AB7", "#3C3489"),
         "deep": ("Deep scan", "#E1F5EE", "#1D9E75", "#085041")}


def _side(label, m, fallback_grade, fallback_at):
    import html as _h
    e = _h.escape
    k = _KIND.get((m or {}).get("kind"), _KIND["free"])
    bits = []
    if (m or {}).get("at") or fallback_at:
        bits.append(e(_when((m or {}).get("at") or fallback_at)))
    if (m or {}).get("areas_total"):
        bits.append(f'{int(m.get("areas_checked") or 0)} of {int(m["areas_total"])} areas checked')
    if (m or {}).get("files"):
        bits.append(f'{int(m["files"])} files read')
    if (m or {}).get("prompts"):
        bits.append(f'{int(m["prompts"])} fix prompt{"" if m["prompts"] == 1 else "s"}')
    g = (m or {}).get("grade") or fallback_grade or "–"
    return (f'<div class="cside" style="background:{k[1]};border-left:4px solid {k[2]};color:{k[3]}">'
            f'<div style="font-size:12px;font-weight:700">{e(label)} &middot; {k[0]}</div>'
            f'<div style="font-size:30px;font-weight:700;line-height:1.1;margin:.15rem 0">{e(g)}</div>'
            f'<div style="font-size:12px">{" &middot; ".join(bits)}</div></div>')


def _tile(n, label, fg, bg, sign=""):
    return (f'<div style="background:{bg};border-radius:10px;padding:.6rem .5rem;text-align:center">'
            f'<div style="font-size:22px;font-weight:700;color:{fg};line-height:1.1">{sign}{n}</div>'
            f'<div style="font-size:12px;color:#444;margin-top:2px">{label}</div></div>')


def render_page_body(result, repo=""):
    """The compare page's main part (no JavaScript; escapes everything itself)."""
    import html as _h
    e = _h.escape
    if not isinstance(result, dict) or not result:
        return '<p>There is no comparison on this report yet.</p>'
    sit = situation(result)
    b, a = result.get("before") or {}, result.get("after") or {}
    top = (f'<div class="eyebrow">Compare scans</div><h1 style="overflow-wrap:anywhere">{e(repo or result.get("previous_repo") or "Your app")}</h1>'
           f'<div class="cpair">{_side("Earlier", b, result.get("grade_before"), result.get("previous_at"))}'
           f'<div class="carrow">&rarr;</div>{_side("Now", a, result.get("grade_after"), result.get("made_at"))}</div>')
    if sit == "not_comparable":
        return top + (f'<div class="chead" style="background:#F1EFE8;color:#444441"><strong>These scans could not be compared.</strong>'
                      f'{e(result.get("reason") or "")}</div>')
    gone, still, new = (result.get(k) or [] for k in ("no_longer_found", "still_found", "new_found"))
    if sit == "incomplete":
        compared = [x for x in ("Auth", "Config", "Database", "API", "Frontend", "Libraries") if x not in (result.get("not_compared") or [])]
        bc = b.get("areas_checked")
        head = ('<div class="chead" style="background:#FAEEDA;color:#633806"><strong>These two scans can&rsquo;t be compared fairly.</strong>'
                + (f'The earlier scan only checked {int(bc)} of {int(b.get("areas_total") or 6)} areas, so its grade was not a full grade. '
                   if bc is not None else "One of the scans did not check most areas. ")
                + 'The new result is the fuller picture of your app; a different grade here does not mean it got worse.</div>')
        chips = "".join(f'<span class="chip ok">{e(x)}</span>' for x in compared) + "".join(
            f'<span class="chip no">{e(x)}</span>' for x in (result.get("not_compared") or []))
        body = (f'<div style="font-size:13px;font-weight:600;margin-top:.9rem">Areas checked in both scans</div><div class="chips">{chips}</div>'
                + (f'<div style="font-size:13px">In {e(", ".join(compared))}: {len(gone)} no longer found, {len(still)} still there, '
                   f'{len(new)} new. The other areas have no earlier result to compare with.</div>' if compared else ""))
        return top + head + body + _groups_html(result) + _notes_html(result)
    if sit == "free_vs_pro":
        more = max(0, int(a.get("prompts") or 0) - int(b.get("prompts") or 0))
        head = ('<div class="chead" style="background:#EEEDFE;color:#3C3489"><strong>What Pro added</strong>'
                'Pro reads more files with a stronger model, so it can find things the free scan could not see. '
                'These are not new problems in your app, just a deeper look.</div>')
        tiles = ('<div class="ctiles">' + _tile(len(new), "Only Pro found", "#3C3489", "#EEEDFE")
                 + _tile(len(still), "Both found", "#444441", "#F1EFE8") + _tile(more, "More fix prompts", "#085041", "#E1F5EE", "+")
                 + '</div>')
        groups = _groups_html(result, labels={"new_found": "Only Pro found", "still_found": "Found by both",
                                              "no_longer_found": "Only the free scan reported"})
        return top + head + tiles + groups + _notes_html(result)
    gb, ga = result.get("grade_before"), result.get("grade_after")
    if improved(result):
        line = (f'{e(gb)} &rarr; {e(ga)}: ' if gb and ga and gb != ga else "") + (
            f'{len(gone)} problem{"" if len(gone) == 1 else "s"} no longer found.' if gone else "a better grade.")
        head = (f'<div class="chead" style="background:#E1F5EE;color:#085041"><strong>{line}</strong>Nice work. Check them below before '
                'treating them as fixed: the AI can word the same issue differently between scans.</div>')
    else:
        head = f'<div class="chead" style="background:#F1EFE8;color:#444441"><strong>{e(headline(result))}</strong>'
        head += ('Some things may still need work. The list below shows what is still there and what is new.</div>' if (still or new)
                 else 'Nothing changed between these two scans.</div>')
    tiles = ('<div class="ctiles">' + _tile(len(gone), "No longer found", "#085041", "#E1F5EE")
             + _tile(len(still), "Still there", "#633806", "#FAEEDA") + _tile(len(new), "New", "#A32D2D", "#FCEBEB") + '</div>')
    return top + head + tiles + _groups_html(result) + _notes_html(result)


def _groups_html(result, labels=None):
    import html as _h
    e = _h.escape
    labels = labels or {}
    out = ""
    for key, label, _fg, _bg in _GROUPS:
        rows = result.get(key) or []
        if not rows:
            continue
        out += (f'<div style="font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#6b6966;'
                f'margin:1rem 0 .15rem">{labels.get(key, label)} &middot; {len(rows)}</div>')
        for r in rows:
            sev = r.get("severity", "")
            sfg, sbg = _SEV.get(sev, ("#444", "#eee"))
            where = " &middot; ".join(e(x) for x in (r.get("area"), r.get("file")) if x)
            if key == "still_found" and r.get("before") and r.get("before") != sev:
                where += f' &middot; was {e(r["before"])}'
            out += (f'<div style="display:flex;align-items:flex-start;gap:10px;padding:.55rem 0;border-top:0.5px solid #e5e3dc">'
                    f'<div style="flex:1;min-width:0"><div style="font-size:14px;color:#1a1917;line-height:1.4">{e(r.get("title", ""))}</div>'
                    f'<div style="font-size:12px;color:#6b6966;margin-top:2px">{where}</div></div>'
                    f'<span style="flex-shrink:0;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;color:{sfg};'
                    f'background:{sbg}">{e(sev)}</span></div>')
    return out


def _notes_html(result):
    import html as _h
    e = _h.escape
    notes = []
    if result.get("files_note"):
        notes.append(e(result["files_note"]))
    notes.append("&ldquo;No longer found&rdquo; means the newer scan did not report it. The AI can word the same issue "
                 "differently between scans, so check the list before treating anything as fixed.")
    return ('<div style="background:#F6F5F2;border-radius:8px;padding:.6rem .8rem;margin-top:1rem;font-size:12px;color:#6b6966;'
            'line-height:1.55">' + "".join(f'<div style="margin:.15rem 0">{n}</div>' for n in notes) + '</div>')


def summary_text(result):
    """The comparison in a few plain lines, for Ask Verilay's context."""
    if not isinstance(result, dict) or not result.get("comparable"):
        return "The two scans could not be compared."
    b, a = result.get("before") or {}, result.get("after") or {}
    lines = [f"Situation: {situation(result)}",
             f"Earlier scan: {b.get('kind', 'free')}, grade {result.get('grade_before') or '?'}, "
             f"{b.get('areas_checked', '?')} of {b.get('areas_total', 6)} areas checked, {b.get('files') or '?'} files read",
             f"Newer scan: {a.get('kind', 'free')}, grade {result.get('grade_after') or '?'}, "
             f"{a.get('areas_checked', '?')} of {a.get('areas_total', 6)} areas checked, {a.get('files') or '?'} files read"]
    for key, label in (("no_longer_found", "No longer found"), ("still_found", "Still there"), ("new_found", "New")):
        for r in (result.get(key) or [])[:12]:
            lines.append(f"{label}: [{r.get('area')}] {r.get('severity')}: {r.get('title')}")
    if result.get("not_compared"):
        lines.append("Not compared (one scan did not check them): " + ", ".join(result["not_compared"]))
    if result.get("files_note"):
        lines.append(result["files_note"])
    return "\n".join(lines)
