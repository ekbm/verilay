"""
IT Review Pack — a printable, checklist-style view of a saved Verilay report,
written for an IT or security person deciding whether to approve an app that
someone else (usually a non-developer colleague) built with an AI tool.

It adds no new analysis. Everything here is read from the report data the
normal scan already saved (secret_scan, osv_scan, crypto_scan, layers,
health), regrouped into:

  1. A suggested decision — clearly a suggestion; the IT person decides.
  2. Rule-based checks (repeatable: same code in, same result out).
  3. The AI review per layer (expert opinion; can vary between runs).
  4. What to fix before approval.
  5. What this review did NOT check, and independent tools to confirm it.
  6. A sign-off block, so the printed page can go on the approval ticket.

Wording rule: "risk reduced and reviewed", never "certified safe".

Standards references are the ones each check genuinely relates to, named by
version (OWASP ASVS 4.0.3 sections, OWASP Top 10 2021 categories). They say
"related to", not "compliant with": a passing row is not a compliance claim.

Free-tier detail is respected: dependency results use counts only, the same
numbers the free report already shows, never package names or advisory ids.

Every value from the report is HTML-escaped. Report text is partly
AI-generated from user-supplied code, so it is treated as untrusted.
"""

from html import escape


# ── Status vocabulary ──────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "pass":    ("Pass",        "#27500A", "#EAF3DE"),
    "warn":    ("Needs fixes", "#92400E", "#FEF3C7"),
    "fail":    ("Fail",        "#A32D2D", "#FCEBEB"),
    "unknown": ("Not checked", "#4a4846", "#f0f0f0"),
}

# What each AI-review layer covers, and the standards it relates to.
_LAYER_INFO = {
    "Auth":      ("Login, sessions and who can do what",
                  "ASVS 4.0.3 V2 Authentication, V3 Session Management · Top 10 2021 A07"),
    "Database":  ("How data is stored and who can read it",
                  "ASVS 4.0.3 V4 Access Control, V5 Validation · Top 10 2021 A01, A03"),
    "API":       ("The app's server endpoints and what they accept",
                  "ASVS 4.0.3 V13 API and Web Service · Top 10 2021 A01"),
    "Config":    ("Settings, environment variables and deployment setup",
                  "ASVS 4.0.3 V14 Configuration · Top 10 2021 A05"),
    "Frontend":  ("What runs in the user's browser",
                  "ASVS 4.0.3 V5 Validation, Sanitization and Encoding · Top 10 2021 A03"),
    "Libraries": ("Third-party packages the app depends on",
                  "ASVS 4.0.3 V14.2 Dependency · Top 10 2021 A06"),
}
_LAYER_ORDER = ["Auth", "Database", "API", "Config", "Frontend", "Libraries"]

_METHOD_LABEL = {"github": "GitHub repository", "zip": "ZIP upload", "url": "Live URL (surface scan)"}


def _status_from_counts(critical, warnings, checked=True):
    if not checked:
        return "unknown"
    if critical:
        return "fail"
    if warnings:
        return "warn"
    return "pass"


def _badge(status):
    label, fg, bg = _STATUS_STYLE[status]
    return (f'<span class="badge" style="color:{fg};background:{bg}">{label}</span>')


def _n(value):
    """Counts from saved reports are ints, but never trust their type."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# ── Building blocks ────────────────────────────────────────────────────────────

def _rule_rows(data):
    """The deterministic checks. Returns (rows_html, worst_status_list)."""
    rows, statuses = [], []

    ss = data.get("secret_scan") or {}
    ss_checked = bool(ss) and _n(ss.get("files_scanned")) > 0
    ss_status = _status_from_counts(_n(ss.get("critical")), _n(ss.get("warnings")), ss_checked)
    if ss_checked:
        ss_result = (f'{_n(ss.get("critical"))} critical, {_n(ss.get("warnings"))} warnings '
                     f'across {_n(ss.get("files_scanned"))} files')
    else:
        ss_result = "Not run for this report"
    rows.append(("Exposed secrets",
                 "API keys, passwords and tokens written into the code",
                 ss_result, ss_status,
                 "ASVS 4.0.3 V6.4 Secret Management · CWE-798"))
    statuses.append(ss_status)

    osv = data.get("osv_scan") or {}
    osv_checked = bool(osv) and _n(osv.get("packages_checked")) > 0
    osv_status = _status_from_counts(_n(osv.get("critical")), _n(osv.get("warnings")), osv_checked)
    if osv_checked:
        osv_result = (f'{_n(osv.get("vulnerabilities_found"))} known vulnerabilities '
                      f'({_n(osv.get("critical"))} serious) in {_n(osv.get("packages_checked"))} packages checked')
    else:
        osv_result = "No dependency list found, or not run for this report"
    rows.append(("Known-vulnerable libraries",
                 "Packages checked against the OSV.dev vulnerability database",
                 osv_result, osv_status,
                 "ASVS 4.0.3 V14.2 Dependency · Top 10 2021 A06"))
    statuses.append(osv_status)

    cs = data.get("crypto_scan") or {}
    cs_checked = bool(cs) and _n(cs.get("files_scanned")) > 0
    cs_status = _status_from_counts(_n(cs.get("critical")), _n(cs.get("warnings")), cs_checked)
    if cs_checked:
        cs_issues = _n(cs.get("warnings")) + _n(cs.get("critical"))
        cs_result = (f'{cs_issues} issue{"" if cs_issues == 1 else "s"} '
                     f'across {_n(cs.get("files_scanned"))} files')
    else:
        cs_result = "Not run for this report"
    rows.append(("Weak cryptography",
                 "Outdated hashes, broken cipher modes, hardcoded keys, small RSA keys",
                 cs_result, cs_status,
                 "ASVS 4.0.3 V6.2 Algorithms · Top 10 2021 A02"))
    statuses.append(cs_status)

    html = "".join(
        f'<tr><td><strong>{escape(name)}</strong><div class="sub">{escape(what)}</div></td>'
        f'<td>{escape(result)}</td><td>{_badge(status)}</td>'
        f'<td class="ref">{escape(ref)}</td></tr>'
        for name, what, result, status, ref in rows
    )
    return html, statuses


def _layer_status(layer):
    st = (layer.get("status") or "").lower()
    return {"critical": "fail", "warning": "warn", "passing": "pass"}.get(st, "unknown")


def _ai_rows(data):
    """One row per AI-reviewed layer. Returns (rows_html, statuses)."""
    by_name = {l.get("name"): l for l in (data.get("layers") or []) if isinstance(l, dict)}
    rows, statuses = [], []
    for name in _LAYER_ORDER:
        what, ref = _LAYER_INFO[name]
        layer = by_name.get(name)
        if not layer:
            status, note = "unknown", "Not reviewed in this report"
        else:
            status = _layer_status(layer)
            issues = [f for f in ((layer.get("expert") or {}).get("findings") or [])
                      if isinstance(f, dict) and (f.get("severity") or "").lower() in ("critical", "warning")]
            if issues:
                note = "; ".join(escape(str(f.get("title", "")))[:120] for f in issues[:3])
                if len(issues) > 3:
                    note += f"; +{len(issues) - 3} more"
            elif (layer.get("status") or "").lower() == "not_checked":
                note = "Not checked: the AI saw no code for this layer in the files it read"
            else:
                note = "No issues found in the files the AI read"
        statuses.append(status)
        rows.append(
            f'<tr><td><strong>{escape(name)}</strong><div class="sub">{escape(what)}</div></td>'
            f'<td>{note if layer else escape(note)}</td><td>{_badge(status)}</td>'
            f'<td class="ref">{escape(ref)}</td></tr>'
        )
    return "".join(rows), statuses


def _fix_items(data):
    """Critical first, then warnings. Each: (severity, title, where, action)."""
    items = []
    for f in ((data.get("secret_scan") or {}).get("findings") or []):
        if not isinstance(f, dict):
            continue
        where = f'{f.get("file", "")}' + (f':{f.get("line")}' if f.get("line") else "")
        items.append((f.get("severity", "warning"), f.get("name", "Exposed secret"),
                      where, f.get("action", "")))
    osv = data.get("osv_scan") or {}
    if _n(osv.get("vulnerabilities_found")):
        items.append(("critical" if _n(osv.get("critical")) else "warning",
                      f'{_n(osv.get("vulnerabilities_found"))} known vulnerabilities in libraries',
                      "dependency files",
                      "Update the affected packages to their fixed versions, then scan again."))
    for f in ((data.get("crypto_scan") or {}).get("findings") or []):
        if not isinstance(f, dict):
            continue
        where = f'{f.get("file", "")}' + (f':{f.get("line")}' if f.get("line") else "")
        items.append(("warning", f.get("name") or f.get("title") or "Weak cryptography",
                      where, f.get("action", "")))
    for layer in (data.get("layers") or []):
        if not isinstance(layer, dict):
            continue
        for f in ((layer.get("expert") or {}).get("findings") or []):
            if not isinstance(f, dict):
                continue
            sev = (f.get("severity") or "").lower()
            if sev not in ("critical", "warning"):
                continue
            # The Libraries layer restates the OSV result already listed above.
            if layer.get("name") == "Libraries" and "OSV" in str(f.get("detail", "")):
                continue
            items.append((sev, f'{layer.get("name", "")}: {f.get("title", "")}',
                          f.get("file", ""), f.get("why_it_matters", "")))
    items.sort(key=lambda i: 0 if i[0] == "critical" else 1)
    return items


# ── Page ───────────────────────────────────────────────────────────────────────

def render_it_review(data, report_id):
    repo = escape(str(data.get("repo", "Unnamed app")))
    method = data.get("input_method", "")
    method_label = escape(_METHOD_LABEL.get(method, method or "Unknown"))
    generated = escape(str(data.get("generated_at", "")))
    rid = escape(str(report_id))
    is_preview = bool(data.get("preview_only")) or method == "url" \
        or (data.get("health") or {}).get("score") is None

    rule_html, rule_statuses = _rule_rows(data)
    ai_html, ai_statuses = _ai_rows(data)
    fixes = _fix_items(data)
    n_crit = sum(1 for f in fixes if f[0] == "critical")
    n_warn = sum(1 for f in fixes if f[0] != "critical")

    # Suggested decision. Deterministic failures weigh the same as AI-flagged
    # critical ones: either is enough to hold approval.
    all_statuses = rule_statuses + ai_statuses
    if is_preview:
        risk, decision, colour = ("Unknown", "Not enough to decide",  "#4a4846")
        why = ("This report came from a live URL, which only shows what the site sends to a browser. "
               "Scan the source code (GitHub or ZIP) before making an approval decision.")
    elif "fail" in all_statuses or n_crit:
        risk, decision, colour = ("High", "Don't approve yet", "#A32D2D")
        why = ("Critical issues must be fixed and the app scanned again before approval."
               if n_crit else
               "A check failed. Fix it and scan the app again before approval.")
    elif "warn" in all_statuses or n_warn:
        risk, decision, colour = ("Medium", "Approve with fixes", "#92400E")
        why = ("No critical issues. Fix the issues listed below, ideally before real or "
               "sensitive data is used.")
    else:
        risk, decision, colour = ("Low", "Approve, within the limits below", "#27500A")
        why = ("No issues found by these checks. Read 'What this review did not check' before "
               "relying on this result.")

    files_total = _n(data.get("files_total"))
    files_read = _n(data.get("files_read"))
    scanned = max(_n((data.get("secret_scan") or {}).get("files_scanned")), files_read)
    coverage = (f"Rule-based checks covered {scanned} file{'' if scanned == 1 else 's'}. "
                f"The AI review read the {files_read} most security-relevant "
                f"file{'' if files_read == 1 else 's'}"
                + (f" of {files_total}." if files_total else "."))

    if fixes:
        fix_html = "".join(
            f'<li><span class="sev {"crit" if sev == "critical" else "warn"}">'
            f'{"Critical" if sev == "critical" else "Warning"}</span> '
            f'<strong>{escape(str(title))}</strong>'
            + (f' <span class="where">{escape(str(where))}</span>' if where else "")
            + (f'<div class="sub">{escape(str(action))}</div>' if action else "")
            + '</li>'
            for sev, title, where, action in fixes[:25]
        )
        if len(fixes) > 25:
            fix_html += f'<li class="sub">+{len(fixes) - 25} more in the full report</li>'
        fix_block = f'<ol class="fixes">{fix_html}</ol>'
    else:
        fix_block = '<p class="sub">Nothing flagged by these checks.</p>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>IT Review Pack — {repo}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8fc;color:#1a1a2e;font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:900px;margin:0 auto;padding:1.5rem}}
.top{{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:1rem}}
.top a{{color:#534AB7;font-size:13px;text-decoration:none}}
.btn{{background:#534AB7;color:#fff;border:none;border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer}}
.card{{background:#fff;border:0.5px solid #e5e5f0;border-radius:12px;padding:1.1rem 1.3rem;margin-bottom:1rem}}
h1{{font-size:22px;margin-bottom:.2rem}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#6b6966;margin:1.4rem 0 .6rem}}
.meta{{font-size:12px;color:#6b6966}}
.banner{{background:#EEEDFE;color:#3C3489;border-radius:8px;padding:.6rem .9rem;font-size:13px;margin-top:.8rem}}
.decision{{display:flex;gap:1.5rem;flex-wrap:wrap;align-items:center}}
.decision .big{{font-size:20px;font-weight:700}}
.decision .lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#6b6966}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b6966;padding:.4rem .5rem;border-bottom:1px solid #e5e5f0}}
td{{padding:.6rem .5rem;border-bottom:0.5px solid #eee;vertical-align:top}}
.sub{{font-size:12px;color:#6b6966}}
.ref{{font-size:11px;color:#6b6966;width:24%}}
.badge{{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;white-space:nowrap}}
.fixes{{padding-left:1.2rem}}
.fixes li{{margin-bottom:.55rem}}
.sev{{font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px;text-transform:uppercase}}
.sev.crit{{background:#FCEBEB;color:#A32D2D}}
.sev.warn{{background:#FEF3C7;color:#92400E}}
.where{{font-family:monospace;font-size:12px;color:#6b6966;word-break:break-all}}
ul.plain{{padding-left:1.2rem}}
ul.plain li{{margin-bottom:.35rem}}
.sign td{{border:none;padding:.5rem 0}}
.line{{border-bottom:1px solid #999;display:inline-block;min-width:220px;max-width:100%;height:1.1rem}}
.box{{display:inline-block;width:12px;height:12px;border:1px solid #555;margin:0 4px 0 12px;vertical-align:-1px}}
.opt{{white-space:nowrap}}
.foot{{font-size:11px;color:#888;text-align:center;margin:1.2rem 0}}
@media(max-width:640px){{.ref{{display:none}}th.refh{{display:none}}.wrap{{padding:1rem}}
  /* Sign-off: the write-in lines have fixed minimum widths (220/140/420px), which pushed the table
     past a phone screen. On small screens each field stacks, with a full-width line under its label. */
  .sign,.sign tbody,.sign tr,.sign td{{display:block;width:100%}}
  .sign td{{padding:.45rem 0}}
  .line{{display:block;min-width:0!important;width:100%;margin-top:.3rem}}}}
@media print{{
  body{{background:#fff;font-size:12px}}
  .noprint{{display:none!important}}
  .card{{border:1px solid #ccc;break-inside:avoid}}
  .wrap{{padding:0;max-width:none}}
  tr{{break-inside:avoid}}
}}
</style></head><body><div class="wrap">

<div class="top noprint">
  <a href="/report/{rid}">&larr; Back to the full report</a>
  <button class="btn" onclick="window.print()">Print or save as PDF</button>
</div>

<div class="card">
  <div class="meta">Verilay · IT Review Pack</div>
  <h1>{repo}</h1>
  <div class="meta">Source: {method_label} · Scanned: {generated} · Report ID: {rid}</div>
  <div class="banner"><strong>Risk reduced and reviewed — not certified safe.</strong>
  This is an automated first-pass review to support an approval decision. It is not a penetration
  test, a security audit or a compliance certification.</div>
</div>

<div class="card">
  <div class="decision">
    <div><div class="lbl">Suggested decision</div><div class="big" style="color:{colour}">{decision}</div></div>
    <div><div class="lbl">Risk level</div><div class="big" style="color:{colour}">{risk}</div></div>
    <div><div class="lbl">To fix</div><div class="big">{n_crit} critical · {n_warn} other</div></div>
  </div>
  <p style="margin-top:.6rem">{escape(why)}</p>
  <p class="sub" style="margin-top:.3rem">This is a suggestion based on the checks below. The approval decision belongs to the reviewer.</p>
</div>

<h2>1 · Rule-based checks (repeatable)</h2>
<div class="card">
  <p class="sub" style="margin-bottom:.5rem">The same code always gives the same result. {escape(coverage)}</p>
  <table><tr><th>Check</th><th>Result</th><th>Status</th><th class="refh">Related standard</th></tr>{rule_html}</table>
</div>

<h2>2 · AI review by area (expert opinion)</h2>
<div class="card">
  <p class="sub" style="margin-bottom:.5rem">Written by an AI model reading the code. Treat it as an
  informed opinion: results can vary slightly between runs, and "no issues found" means none were seen
  in the files read, not that the area is proven secure.</p>
  <table><tr><th>Area</th><th>Findings</th><th>Status</th><th class="refh">Related standard</th></tr>{ai_html}</table>
</div>

<h2>3 · Fix before approval</h2>
<div class="card">{fix_block}</div>

<h2>4 · What this review did not check</h2>
<div class="card">
  <ul class="plain">
    <li><strong>The running app.</strong> This review reads code. It did not test the live site, its hosting or its network setup.</li>
    <li><strong>Whether one user can see another user's data</strong> in practice. Confirm with a two-account test.</li>
    <li><strong>Settings made outside the code</strong>, such as database access rules or login options set in a Supabase, Firebase or hosting dashboard.</li>
    <li><strong>Where company data goes:</strong> which outside services, AI providers and countries receive it.</li>
    <li><strong>Sign-in requirements:</strong> whether it supports company single sign-on (SSO) or enforces two-factor login.</li>
    <li><strong>Software licences</strong> of the libraries used.</li>
    <li><strong>Business logic:</strong> whether the app does the right thing for your processes.</li>
    <li><strong>AI-specific risks</strong> if the app itself calls an AI model, such as prompt injection.</li>
    <li><strong>Files the AI did not read.</strong> The rule-based checks cover every file; the AI review covers the most relevant ones only.</li>
  </ul>
</div>

<h2>5 · Confirm independently</h2>
<div class="card">
  <p class="sub" style="margin-bottom:.5rem">Free, widely used tools your team can run without Verilay:</p>
  <table>
    <tr><th>What</th><th>Tool</th></tr>
    <tr><td>Known-vulnerable libraries</td><td>OSV-Scanner (google/osv-scanner)</td></tr>
    <tr><td>Code security bugs</td><td>Semgrep community rules</td></tr>
    <tr><td>Secrets in code and history</td><td>Gitleaks</td></tr>
    <tr><td>Live site, passive scan (with the owner's permission)</td><td>OWASP ZAP baseline scan</td></tr>
  </table>
</div>

<h2>6 · Sign-off</h2>
<div class="card">
  <table class="sign">
    <tr><td>Reviewed by: <span class="line"></span></td><td>Date: <span class="line" style="min-width:140px"></span></td></tr>
    <tr><td colspan="2">Decision:<span class="opt"><span class="box"></span>Approve</span><span class="opt"><span class="box"></span>Approve with fixes</span><span class="opt"><span class="box"></span>Don't approve</span></td></tr>
    <tr><td colspan="2">Conditions or notes: <span class="line" style="min-width:420px"></span></td></tr>
  </table>
</div>

<p class="foot">Generated by Verilay (verilay.dev) from report {rid}. AI-assisted analysis may contain false
positives or miss issues. Not a professional security audit. See verilay.dev/ai-disclaimer.</p>
</div></body></html>"""
