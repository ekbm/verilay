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
        }).eq("app_name", app_name).execute()
        print(f"[self-monitor] {app_name}: {score} ({crit} critical, {warn} warnings)", flush=True)
    except Exception as e:
        print(f"[self-monitor] scan failed for {app_name}: {e}", flush=True)


def widget_html():
    """Aggregate-only teaser for the landing page. Returns '' if Supabase
    isn't configured or no app has completed its first check yet — never
    shows a half-populated or broken-looking widget."""
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
    most_recent = max(r["last_checked_at"] for r in checked)
    age = _human_age(most_recent)

    resolved = 0
    for r in checked:
        pc, pw = r.get("prev_critical"), r.get("prev_warnings")
        if pc is None or pw is None:
            continue
        delta = (pc + pw) - (r["critical"] + r["warnings"])
        if delta > 0:
            resolved += delta

    resolved_line = (
        f" · {resolved} issue{'s' if resolved != 1 else ''} resolved since the last check"
        if resolved > 0 else ""
    )

    return (
        '<div style="border:0.5px solid var(--bdr);border-radius:var(--r);padding:.75rem 1rem;'
        'margin-bottom:10px;font-size:13px;color:var(--mut)">'
        f'<span style="color:var(--gr)">●</span> Verilay continuously monitors {len(checked)} '
        f'of its own apps — {names}. Not just a one-time check.'
        f'<div style="margin-top:4px">Last checked {age}{resolved_line}.</div>'
        '</div>'
    )


def _human_age(iso_ts):
    try:
        then = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return "recently"
    delta = datetime.now(timezone.utc) - then
    minutes = delta.total_seconds() / 60
    if minutes < 60:
        return "less than an hour ago"
    hours = minutes / 60
    if hours < 24:
        n = int(hours)
        return f"{n} hour{'s' if n != 1 else ''} ago"
    days = int(hours / 24)
    return f"{days} day{'s' if days != 1 else ''} ago"
