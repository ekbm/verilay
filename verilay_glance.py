"""verilay_glance.py - the "Scan At A Glance" panel on a finished report.

Shows, in numbers, what a scan actually covered: how much of the repository each check read, what the
dependency check found, how each area scored and what the repository is made of. Everything is taken from
data the report already holds; nothing here runs a new analysis and nothing is guessed.

`render_glance_html(data)` expects the report data AFTER it has been HTML-escaped (the report page escapes
the whole tree once), so strings are used as they are. It returns "" when there is nothing sensible to show
(for example a website-only preview), so the caller can always append the result.
"""
import html as _html
import re

_ACCENT = "#534AB7"
_TRACK = "#F1EFE8"

_AREA_STYLE = {
    "passing":     ("#085041", "#E1F5EE", "&#10003;", "no issues seen"),   # "passing" would read as "all fine"
    "warning":     ("#633806", "#FAEEDA", "&#9650;", "warning"),
    "critical":    ("#791F1F", "#FCEBEB", "&#9632;", "critical"),
    "not_checked": ("#444441", "#F1EFE8", "&ndash;", "not checked"),
}

# What categorise_files() calls things, in words a non-developer reads easily.
_FILE_KIND = (
    ("data",   "Logins and data", "#534AB7"),
    ("visual", "Pages and visuals", "#1D9E75"),
    ("config", "Settings", "#EF9F27"),
    ("libs",   "Bundled libraries", "#888780"),
    ("other",  "Everything else", "#B4B2A9"),
)


def _i(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _n(value):
    return f"{_i(value):,}"


def _pct(part, whole):
    whole = _i(whole)
    return 0 if not whole else max(0, min(100, round(100 * _i(part) / whole)))


def _meter(pct, color=_ACCENT):
    return (f'<div style="height:6px;background:{_TRACK};border-radius:3px;overflow:hidden">'
            f'<div style="height:100%;width:{pct}%;background:{color};border-radius:3px"></div></div>')


def _row(label, pct, value, color=_ACCENT):
    return ('<div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px 14px;padding:8px 0;'
            'border-top:0.5px solid #e5e5f0;font-size:13px">'
            f'<div style="flex:0 0 150px;font-weight:600;color:#333">{label}</div>'
            f'<div style="flex:1 1 120px;min-width:100px">{_meter(pct, color)}</div>'
            f'<div style="flex:0 0 285px;max-width:100%;color:#666;text-align:right">{value}</div></div>')


def _stack_bar(parts):
    """parts = [(count, colour, label)]. A single bar plus a legend that carries the numbers."""
    parts = [p for p in parts if p[0] > 0]
    if not parts:
        return ""
    bar = "".join(f'<div style="flex:{c};background:{col}"></div>' for c, col, _ in parts)
    legend = "".join(
        f'<span style="white-space:nowrap"><span style="display:inline-block;width:9px;height:9px;'
        f'border-radius:2px;background:{col};margin-right:5px"></span>{lab} ({_n(c)})</span>'
        for c, col, lab in parts)
    return (f'<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;gap:2px">{bar}</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:8px;font-size:12px;color:#666">{legend}</div>')


def _minutes(text):
    """'30 minutes' -> 30, '1 hour' -> 60, '1-2 hours' -> 120 (the larger end). None if unreadable."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*(?:-|to|&ndash;|–)?\s*(\d+(?:\.\d+)?)?\s*(min|hour|hr|day)", str(text or "").lower())
    if not m:
        return None
    n = float(m.group(2) or m.group(1))
    return round(n * {"min": 1, "hour": 60, "hr": 60, "day": 480}[m.group(3)])


def fix_time_label(top_fixes):
    """'about 3.5 hours' for the listed fixes, or "" if any estimate can't be read (then we say nothing)."""
    fixes = [f for f in (top_fixes or []) if isinstance(f, dict)]
    if not fixes:
        return ""
    mins = [_minutes(f.get("estimated_effort")) for f in fixes]
    if any(m is None for m in mins):
        return ""
    total = sum(mins)
    if total < 60:
        return f"about {total} minutes"
    hours = round(total / 60 * 2) / 2
    return f"about {hours:g} hour" + ("" if hours == 1 else "s")


def render_glance_html(data):
    data = data or {}
    health = data.get("health") or {}
    if data.get("preview_only") or health.get("score") is None or data.get("analysis_incomplete"):
        return ""

    total = _i(data.get("files_total"))
    read = _i(data.get("files_read"))
    rows = []

    if read and total:
        rows.append(_row("AI code review", _pct(read, total), f"{_n(read)} of {_n(total)} files ({_pct(read, total)}%)"))

    for label, block in (("Secret scan", data.get("secret_scan")), ("Weak-crypto scan", data.get("crypto_scan"))):
        scanned = _i((block or {}).get("files_scanned"))
        if scanned:
            every = total and scanned >= total
            value = f"All {_n(scanned)} files" if every else f"{_n(scanned)} of {_n(total)} files"
            colour = _ACCENT
            # A hint that needs a person to look: never show the row as a clean, complete pass.
            to_check = len([n for n in ((block or {}).get("notes") or []) if isinstance(n, dict)])
            if to_check:
                value += f" &middot; {to_check} to check"
                colour = "#BA7517"
            rows.append(_row(label, 100 if every else _pct(scanned, total or scanned), value, colour))

    osv = data.get("osv_scan") or {}
    checked = _i(osv.get("packages_checked"))
    vulns = osv.get("vulnerabilities")
    found = _i(osv.get("vulnerabilities_found")) if osv.get("vulnerabilities_found") is not None else (len(vulns) if isinstance(vulns, list) else 0)
    if checked:
        rows.append(_row("Dependencies", 100, f"{_n(checked)} packages &middot; {_n(found)} "
                         + ("vulnerable package" if found == 1 else "vulnerable packages")))
    else:
        rows.append(_row("Dependencies", 0, "No package list found in the files read"))

    authz = data.get("authz_scan") or {}
    if authz.get("applicable"):
        rows.append(_row("Access rules (Supabase)", 100,
                         f"{_n(authz.get('critical'))} definite &middot; {_n(authz.get('review'))} to review"))
    else:
        rows.append(_row("Access rules (Supabase)", 0, "Not applicable, no Supabase database files found"))

    cov = osv.get("coverage") if isinstance(osv.get("coverage"), dict) else {}
    cov_note = ""
    if cov.get("summary") or cov.get("note"):
        cov_note = ('<div style="font-size:12px;color:#888;margin-top:.5rem">Dependencies: '
                    + " ".join(str(x).rstrip(". ") + "." for x in (cov.get("summary"), cov.get("note")) if x) + "</div>")

    checked_card = ('<div class="card"><div style="font-size:13px;font-weight:600;color:#333;margin-bottom:.1rem">'
                    'What was checked</div>' + "".join(rows) + cov_note + "</div>")

    chips = ""
    for layer in data.get("layers") or []:
        if not isinstance(layer, dict):
            continue
        fg, bg, icon, word = _AREA_STYLE.get(layer.get("status"), _AREA_STYLE["not_checked"])
        chips += (f'<span style="display:inline-flex;align-items:center;gap:6px;background:{bg};color:{fg};'
                  f'font-size:12px;padding:5px 11px;border-radius:8px"><span aria-hidden="true">{icon}</span>'
                  f'{layer.get("name", "")} &middot; {word}</span>')
    areas_card = ('<div class="card"><div style="font-size:13px;font-weight:600;color:#333;margin-bottom:.6rem">'
                  f'Health by area</div><div style="display:flex;flex-wrap:wrap;gap:8px">{chips}</div></div>'
                  ) if chips else ""

    cards = []
    if checked and found:
        if isinstance(vulns, list):
            crit = _i(osv.get("critical"))
            high = _i(osv.get("high"))
            parts = [(crit, "#A32D2D", "critical"), (high, "#D85A30", "high"),
                     (max(0, found - crit - high), "#888780", "lower")]
        else:
            crit = _i(osv.get("critical"))
            parts = [(crit, "#A32D2D", "critical"), (max(0, found - crit), "#888780", "lower")]
        cards.append('<div class="card" style="margin:0"><div style="font-size:13px;font-weight:600;color:#333;'
                     f'margin-bottom:.6rem">Known issues in your packages ({_n(found)})</div>{_stack_bar(parts)}</div>')

    mix = {str(b.get("key")): _i(b.get("count")) for b in (data.get("file_breakdown") or []) if isinstance(b, dict)}
    mix_total = sum(mix.values())
    if mix_total:
        scope = ("the files Verilay read" if read and mix_total == read
                 else "every file in the repository" if total and mix_total == total else "the files counted")
        parts = [(mix.get(k, 0), col, lab)
                 for k, lab, col in _FILE_KIND]
        cards.append('<div class="card" style="margin:0"><div style="font-size:13px;font-weight:600;color:#333;'
                     f'margin-bottom:.6rem">What it is made of ({_n(mix_total)} files, {scope})</div>'
                     f'{_stack_bar(parts)}</div>')

    grid = ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:.75rem">'
            + "".join(cards) + "</div>") if cards else ""

    est = fix_time_label(data.get("top_fixes"))
    n_fixes = len([f for f in (data.get("top_fixes") or []) if isinstance(f, dict)])
    est_line = (f'<div style="font-size:12px;color:#888;margin-top:.75rem">Estimated time for the {n_fixes} priority '
                f'fix{"" if n_fixes == 1 else "es"} above: {est}. These are the AI\'s own estimates, not a promise, '
                'and package updates are extra.</div>') if est else ""

    return ('<div class="st">Scan At A Glance</div>' + checked_card + areas_card + grid + est_line)


_GRADE_COLOUR = {"A": ("#085041", "#E1F5EE"), "B": ("#0C447C", "#E6F1FB"), "C": ("#633806", "#FAEEDA"),
                 "D": ("#791F1F", "#FCEBEB"), "F": ("#791F1F", "#FCEBEB")}


def sample_preview_html(data, report_id, label=""):
    """The homepage's example-report card. Built from a SAVED free report (raw, un-escaped data: this function escapes
    everything itself) so the numbers can never disagree with the report the 'See a sample report' button opens.
    Returns "" when the report can't be shown (missing, website-only preview, incomplete)."""
    data = data or {}
    health = data.get("health") or {}
    score = str(health.get("score") or "").strip().upper()[:1]
    if score not in _GRADE_COLOUR or data.get("preview_only") or data.get("analysis_incomplete"):
        return ""
    if not re.fullmatch(r"[0-9a-f]{12}", str(report_id or "")):
        return ""
    esc = lambda s: _html.escape(str(s if s is not None else ""), quote=True)
    fg, bg = _GRADE_COLOUR[score]

    chips = ""
    for layer in data.get("layers") or []:
        if not isinstance(layer, dict):
            continue
        cfg, cbg, icon, word = _AREA_STYLE.get(layer.get("status"), _AREA_STYLE["not_checked"])
        chips += (f'<span style="background:{cbg};color:{cfg};font-size:11px;font-weight:700;padding:4px 10px;'
                  f'border-radius:8px;white-space:nowrap" title="{word}"><span aria-hidden="true">{icon}</span> '
                  f'{esc(layer.get("name"))}<span style="position:absolute;left:-9999px"> {word}</span></span>')

    read, total = _i(data.get("files_read")), _i(data.get("files_total"))
    scanned = _i((data.get("secret_scan") or {}).get("files_scanned"))
    cover = ""
    if read and total:
        cover = f"The AI read {_n(read)} of {_n(total)} files"
        if scanned >= total:
            cover += f"; the secret scan covered all {_n(total)}"
        cover = f'<div style="font-size:12px;color:#6b6966;margin-top:8px">{cover}.</div>'

    sub = esc(label) if label else "A real report from a Verilay free scan"
    return (
        '<div style="background:#fff;border:0.5px solid #d6d1f5;border-radius:14px;padding:14px 16px;max-width:680px;'
        'margin:1.25rem auto 0;text-align:left">'
        '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">'
        f'<div style="background:{bg};color:{fg};font-size:38px;font-weight:900;border-radius:12px;width:64px;height:64px;'
        f'display:flex;align-items:center;justify-content:center;flex-shrink:0" aria-label="Grade {score}">{score}</div>'
        '<div style="flex:1;min-width:180px"><div style="font-weight:800;font-size:15px;color:#1a1917">'
        f'Sample report: {esc(data.get("repo"))}</div>'
        f'<div style="font-size:12px;color:#6b6966;line-height:1.45">{sub}</div></div>'
        '<div style="display:flex;gap:16px;font-size:12px;color:#6b6966;text-align:center">'
        f'<span><b style="font-size:22px;color:#A32D2D;display:block;line-height:1.1">{_n(health.get("critical"))}</b>critical</span>'
        f'<span><b style="font-size:22px;color:#BA7517;display:block;line-height:1.1">{_n(health.get("warnings"))}</b>warnings</span>'
        f'<span><b style="font-size:22px;color:#0F6E56;display:block;line-height:1.1">{_n(health.get("passing"))}</b>no issues seen</span>'
        '</div></div>'
        + (f'<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:10px">{chips}</div>' if chips else "")
        + cover
        + f'<a href="/report/{report_id}" target="_blank" rel="noopener" '
          'onclick="try{if(window.plausible)plausible(\'Homepage Sample Card Click\')}catch(e){}" '
          'style="display:inline-block;font-size:13px;font-weight:700;color:#534AB7;margin-top:10px">'
          'See the full sample report &rarr;</a></div>'
    )
