"""
verilay_self_monitor.py — the "we monitor our own apps" landing-page teaser.

Aggregate status only, deliberately: never store or show which specific
vulnerabilities are currently open on Moses's own live production apps
(BuildBook, Verilay, Loginsight once added) — that would publish a target
list against his own products. Only a score and critical/warning COUNTS are
kept, plus the previous check's counts so the landing page can say "N issues
resolved since last check" without ever naming what they were.

No external cron needed — piggybacks on ordinary homepage traffic. maybe_tick()
is cheap (one indexed query) when nothing is due, and only starts a scan when
an app is genuinely overdue (CHECK_INTERVAL_DAYS). Railway runs 4 Gunicorn
workers, so the "is anything due" check and the "claim it" update are two
separate steps: the claim is a conditional UPDATE that only succeeds if the
row STILL looks overdue at that exact moment, so if two workers race, only one
of them actually gets rows back and starts a scan — same atomic-claim pattern
Stripe webhook idempotency already uses elsewhere in this codebase, just via
a WHERE clause instead of a unique constraint.

Kept dependency-injected (configure(), called once from app.py) rather than
importing app.py directly, to avoid a circular import — same pattern as
verilay_deepscan.py, and deliberately reuses its exact free-analysis
functions rather than duplicating them.
"""
import threading
from datetime import datetime, timedelta, timezone

CHECK_INTERVAL_DAYS = 7
MAX_FILES = 25  # same depth as a normal free scan — this is a teaser, not a deep scan

_deps = {}


def configure(**kwargs):
    _deps.update(kwargs)


def _sb():
    return _deps.get("supabase_client")


def _cutoff_iso():
    return (datetime.now(timezone.utc) - timedelta(days=CHECK_INTERVAL_DAYS)).isoformat()


def maybe_tick():
    """Call on a normal page load. Does nothing (one cheap query) unless an
    app is actually overdue. Never raises — a failure here must never break
    the homepage for a real visitor."""
    sb = _sb()
    if sb is None:
        return
    try:
        cutoff = _cutoff_iso()
        due = (sb.table("self_monitoring")
                 .select("app_name,repo")
                 .lt("last_checked_at", cutoff)
                 .order("last_checked_at")
                 .limit(1)
                 .execute())
        if not due.data:
            return
        row = due.data[0]
        # Atomic claim: this UPDATE only affects a row if it is STILL overdue
        # right now — if another worker claimed it a moment ago, last_checked_at
        # is already fresh and this WHERE clause matches nothing.
        claim = (sb.table("self_monitoring")
                   .update({"last_checked_at": datetime.now(timezone.utc).isoformat()})
                   .eq("app_name", row["app_name"])
                   .lt("last_checked_at", cutoff)
                   .execute())
        if not claim.data:
            return  # lost the race to another worker — fine, it's covered
        t = threading.Thread(target=_run_scan, args=(row["app_name"], row["repo"]), daemon=True)
        t.start()
    except Exception as e:
        print(f"[self-monitor] tick failed (non-critical): {e}", flush=True)


def _run_scan(app_name, repo):
    sb = _sb()
    try:
        owner, _, name = repo.partition("/")
        all_files = _deps["fetch_all_files_tarball"](owner, name, _deps["github_token"]())
        if not all_files:
            raise ValueError(f"could not read any files from {repo}")

        selected = _deps["smart_file_selection"](all_files, max_files=MAX_FILES)
        files = {p: all_files[p][:_deps["max_file_chars"]] for p in selected}

        scan_findings = _deps["scan_repo"](all_files)
        scan_critical = sum(1 for f in scan_findings if f.severity == "critical")
        scan_warning = sum(1 for f in scan_findings if f.severity == "warning")

        osv_vulns, osv_checked = _deps["check_dependencies"](all_files)
        osv_critical, osv_warning = _deps["osv_severity_counts"](osv_vulns)

        scan_block = _deps["secret_to_prompt_block"](scan_findings, len(all_files))
        osv_block = _deps["osv_to_prompt_block"](osv_vulns, osv_checked)
        s2 = _deps["analyse_step2"](files, repo, scan_block)
        s3 = _deps["analyse_step3"](files, repo, osv_block)

        crit = warn = 0
        for layer in s2.get("layers", []) + s3.get("layers", []):
            for f in layer.get("expert", {}).get("findings", []):
                sev = (f.get("severity") or "").lower()
                if sev == "critical":
                    crit += 1
                elif sev == "warning":
                    warn += 1
        # Same deterministic floor the free/paid scans already use — a
        # scanner-confirmed fact can't be talked under by layer findings.
        crit = max(crit, scan_critical, osv_critical)
        warn = max(warn, scan_warning, osv_warning)
        score = _deps["grade_from_counts"](crit, warn)

        # Grab the PREVIOUS counts before overwriting them, so the widget can
        # show a resolved delta without ever exposing the absolute numbers.
        prev = sb.table("self_monitoring").select("critical,warnings").eq("app_name", app_name).execute()
        prev_row = prev.data[0] if prev.data else {}

        sb.table("self_monitoring").update({
            "score": score,
            "critical": crit,
            "warnings": warn,
            "prev_critical": prev_row.get("critical"),
            "prev_warnings": prev_row.get("warnings"),
            "last_checked_at": datetime.now(timezone.utc).isoformat(),
            "last_error": None,  # clear any stale error now that a scan actually succeeded
        }).eq("app_name", app_name).execute()
        print(f"[self-monitor] {app_name}: {score} ({crit} critical, {warn} warnings)", flush=True)
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"[:500]
        print(f"[self-monitor] scan failed for {app_name}: {err_text}", flush=True)
        # maybe_tick() already marked this app "checked" (last_checked_at=now)
        # the moment it claimed the row, before this scan ran — so a FAILED
        # scan looks identical to a successful one and would otherwise sit
        # untried for the full CHECK_INTERVAL_DAYS. Back the timestamp off
        # so the next homepage visit picks it up again shortly instead of a
        # week from now. Best-effort — if even this fails, worst case is the
        # original 7-day wait, not a crash. Also persist the actual error so
        # it's visible from /self-monitor-health without needing Railway log
        # access — Supabase's own dashboard logs are a different system and
        # never show these application-level prints.
        try:
            retry_at = datetime.now(timezone.utc) - timedelta(days=CHECK_INTERVAL_DAYS) + timedelta(hours=1)
            sb.table("self_monitoring").update(
                {"last_checked_at": retry_at.isoformat(), "last_error": err_text}
            ).eq("app_name", app_name).execute()
        except Exception:
            pass


def health_data():
    """Diagnostic dict for /self-monitor-health — exists so a failure can be
    diagnosed by looking at a URL instead of digging through Railway's log
    viewer (Supabase's own dashboard logs are a different system and never
    show these prints). Safe to expose: an error like "404 from GitHub" is
    an access/infra fact, not a vulnerability finding about any app's actual
    security posture, so it doesn't violate the "never show real findings
    publicly" rule the rest of this module follows."""
    sb = _sb()
    if sb is None:
        return {"configured": False}
    try:
        res = sb.table("self_monitoring").select("*").order("app_name").execute()
        rows = res.data or []
    except Exception as e:
        return {"configured": True, "error": f"could not read self_monitoring table: {e}"}
    return {
        "configured": True,
        "check_interval_days": CHECK_INTERVAL_DAYS,
        "apps": [
            {
                "app_name": r.get("app_name"),
                "repo": r.get("repo"),
                "score": r.get("score"),
                "last_checked_at": r.get("last_checked_at"),
                "last_error": r.get("last_error"),
            }
            for r in rows
        ],
    }


def badge_html():
    """The real, live status pill. CRO review (2026-08-18) found the combined
    badge+table sitting above the H1 was delaying the page's core message and
    eating into above-the-fold space on mobile — split so the badge (short,
    skimmable) can stay near the hero's other social-proof badge, while the
    heavier example table (below) moves down to where the reader already has
    context. Returns '' if Supabase isn't configured or no app has completed
    its first check yet — never shows a half-populated or broken-looking badge.

    Safety property, unchanged from the muted version this replaced: a ZERO
    open-issue count is fine to show precisely (it's good news, reveals
    nothing) — but a NON-ZERO count is never shown as a number, only ever as
    a positive "N resolved" delta. Bold styling doesn't change what data is
    safe to expose, only how visible the honest version of it is."""
    sb = _sb()
    if sb is None:
        return ""
    try:
        res = sb.table("self_monitoring").select("*").order("app_name").execute()
        rows = res.data or []
    except Exception:
        return ""

    checked = [r for r in rows if r.get("score")]
    if not checked:
        return ""

    names = ", ".join(r["app_name"] for r in checked)
    total_open = sum(r["critical"] + r["warnings"] for r in checked)

    resolved = 0
    for r in checked:
        pc, pw = r.get("prev_critical"), r.get("prev_warnings")
        if pc is None or pw is None:
            continue
        delta = (pc + pw) - (r["critical"] + r["warnings"])
        if delta > 0:
            resolved += delta

    if total_open == 0:
        detail = "0 issues found — all clear right now"
    elif resolved > 0:
        detail = f"{resolved} issue{'s' if resolved != 1 else ''} resolved since the last check"
    else:
        detail = ""

    detail_html = f" &nbsp;·&nbsp; {detail}" if detail else ""

    return (
        '<div style="display:inline-flex;align-items:center;gap:8px;background:var(--grl);'
        'color:var(--grt);font-size:13px;font-weight:600;padding:5px 16px;border-radius:20px;'
        'display:inline-block">'
        '<span style="width:8px;height:8px;border-radius:50%;background:var(--gr);'
        'display:inline-block;flex-shrink:0"></span>'
        f'Continuously monitoring {len(checked)} of our own apps — {names}{detail_html}'
        '</div>'
    )


# Illustrative only — deliberately NOT sourced from real scan data. The badge
# above is the real, live proof; this exists purely to show the DEPTH of
# what continuous monitoring checks for, without ever putting a real app's
# actual findings on a public page. Numbers are made up on purpose.
_SAMPLE_LIBRARY_FINDINGS = [
    ("Outdated / unpatched dependency", "critical", 4),
    ("Known CVE in a third-party package", "critical", 2),
    ("Prototype pollution", "warning", 1),
    ("Regular expression DoS (ReDoS)", "warning", 1),
]


def sample_table_html():
    rows = "".join(
        '<tr style="border-top:0.5px solid var(--bdr)">'
        f'<td style="padding:6px 10px;font-size:12px;color:var(--txt);text-align:left">{name}</td>'
        f'<td style="padding:6px 10px;font-size:12px;font-weight:700;text-align:center;'
        f'color:{"var(--rdt)" if sev == "critical" else "var(--ort)"}">{count}</td>'
        '</tr>'
        for name, sev, count in _SAMPLE_LIBRARY_FINDINGS
    )
    return (
        '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;'
        'max-width:420px;margin:0 auto 1rem;text-align:left">'
        '<div style="font-size:11px;font-weight:600;color:var(--mut);text-transform:uppercase;'
        'letter-spacing:.05em;margin-bottom:6px">Example — the level of detail a deep scan digs up in your dependencies</div>'
        '<table style="width:100%;border-collapse:collapse">'
        '<tr><th style="padding:4px 10px;font-size:11px;color:var(--mut);text-align:left">Vulnerability type</th>'
        '<th style="padding:4px 10px;font-size:11px;color:var(--mut);text-align:center">Found</th></tr>'
        f'{rows}'
        '</table>'
        '<div style="font-size:11px;color:var(--mut);margin-top:8px">'
        'Illustrative example — not real data from a specific app. Your free report already tells you '
        'how many vulnerabilities exist; the <a href="/deep-scan" target="_blank" rel="noopener" '
        'style="color:var(--pu)">deep scan</a> tells you exactly which ones, and how to fix each.</div>'
        '</div>'
    )
