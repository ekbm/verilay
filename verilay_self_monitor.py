"""
verilay_self_monitor.py — the "we monitor our own apps" landing-page teaser.

Aggregate status only, deliberately: never store or show which specific
vulnerabilities are currently open on Moses's own live production apps
(BuildBook, Verilay, Loginsight once added) — that would publish a target
list against his own products. Only a score and critical/warning COUNTS are
kept, plus the previous check's counts so the landing page can say "N issues
resolved since last check" without ever naming what they were.

maybe_tick() is cheap (one indexed query) when nothing is due, and only starts
a scan when an app is genuinely overdue (CHECK_INTERVAL_HOURS). Railway runs 4
Gunicorn workers, so the "is anything due" check and the "claim it" update are
two separate steps: the claim is a conditional UPDATE that only succeeds if the
row STILL looks overdue at that exact moment, so if two workers race, only one
of them actually gets rows back and starts a scan — same atomic-claim pattern
Stripe webhook idempotency already uses elsewhere in this codebase, just via
a WHERE clause instead of a unique constraint.

UPDATE 2026-09-15: originally ticked ONLY on ordinary homepage traffic, with
no external cron — deliberate, Moses's call. On 2026-08-19 he also had the
"checked X ago" figure removed from the badge, because on a quiet traffic day
CHECK_INTERVAL_DAYS (then 7) meant that figure could grow to look stale,
undercutting the word "Continuously" right next to it. Both calls made sense
for a traffic-only design. Moses has now asked for the timestamp back, so
start_scheduler() adds a real timer loop (still calling the same maybe_tick(),
same atomic claim — no new mechanism, just a second trigger for the existing
one) so a check can no longer depend on traffic showing up. CHECK_INTERVAL_HOURS
dropped from 7 days to 24 hours to match: worst case the badge now reads
"checked ~23 hours ago," never the multi-day figure that caused the original
complaint.

UPDATE 2026-10-22 (Moses's decision, after the AI cost figures showed a daily full scan of every app costs about US$1 each): an
app is now scanned only WHEN ITS CODE HAS CHANGED. Each due check first asks GitHub for the newest commit (one free call). If it is
the commit the last successful scan read, with the same scan rules (ANALYSIS_VERSION), and that scan is under
RESCAN_UNCHANGED_DAYS old, nothing is scanned and no AI is used. Any doubt (no stored commit, GitHub did not answer, an earlier
error, a new scan rule) means the scan runs as before. The landing-page badge no longer shows a "last checked" time, because with
this design a check that finds nothing new is correctly silent; the admin table shows when the last REAL scan happened.

Kept dependency-injected (configure(), called once from app.py) rather than
importing app.py directly, to avoid a circular import — same pattern as
verilay_deepscan.py, and deliberately reuses its exact free-analysis
functions rather than duplicating them.
"""
import html as _html
import threading
import time
from datetime import datetime, timedelta, timezone

import verilay_deepwatch as deepwatch
import verilay_notify as notify
import verilay_usage as usage
import verilay_livewatch as livewatch

CHECK_INTERVAL_HOURS = 24
RESCAN_UNCHANGED_DAYS = 30   # even when the code is the same, look again after this long: new vulnerabilities are published for old code
RESOLVED_LOG_MAX = 200  # newest fixed-issue entries kept per app
MAX_FILES = 25  # same depth as a normal free scan — this is a teaser, not a deep scan
SCHEDULER_TICK_SECONDS = 30 * 60  # frequent enough that both apps stay comfortably
                                   # inside CHECK_INTERVAL_HOURS regardless of traffic

_deps = {}
_scheduler_started = False
_scheduler_lock = threading.Lock()


def configure(**kwargs):
    _deps.update(kwargs)


def _sb():
    return _deps.get("supabase_client")


def _cutoff_iso():
    return (datetime.now(timezone.utc) - timedelta(hours=CHECK_INTERVAL_HOURS)).isoformat()


def start_scheduler():
    """Traffic-independent ticking. Call once at app startup (app.py, right
    after self_monitor.configure()). Safe to call from every Gunicorn worker —
    each just runs its own copy of this loop, and maybe_tick()'s atomic claim
    is what actually prevents two workers from double-scanning the same app,
    exactly as it already does for page-load-triggered ticks.

    Guarded against starting twice in the same process (e.g. a module reload
    in a debug server) — a second loop would just waste a thread, not corrupt
    anything, but there's no reason to allow it."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    def _loop():
        while True:
            maybe_tick()
            live_round()
            time.sleep(SCHEDULER_TICK_SECONDS)

    threading.Thread(target=_loop, daemon=True).start()


def live_round():
    """The free daily look at one monitored app's LIVE site (verilay_livewatch.py): headers, https redirect, certificate. No AI, no code.
    At most one app per call; never raises."""
    try:
        livewatch.tick(_sb(), notify.send_live_watch_alert)
    except Exception as e:
        print(f"[self-monitor] live-site round skipped: {type(e).__name__}: {e}", flush=True)


REFRESH_EVERY_SECONDS = 600
_last_refresh = {"at": 0.0}


def refresh_deep_status(now_ts=None):
    """Bring the "deep scan recommended" status up to date when a newer deep scan exists.

    The recommendation used to be worked out only by each app's daily check, so after the owner ran a deep scan the
    monitoring page kept saying "deep scan needed", with the old date, for up to a day. This runs on every scheduler
    tick (throttled to once per REFRESH_EVERY_SECONDS per process) and touches ONLY the deep-scan part of the stored
    status of an app whose newest deep scan is not the one already shown. Database only: no GitHub calls, no AI, no
    emails, and the daily check's own data (findings, head commit, last check time) is left alone.
    Returns how many apps were refreshed. Never raises."""
    sb = _sb()
    if sb is None:
        return 0
    ts = now_ts if now_ts is not None else time.time()
    if ts - _last_refresh["at"] < REFRESH_EVERY_SECONDS:
        return 0
    _last_refresh["at"] = ts
    done = 0
    try:
        now = datetime.now(timezone.utc)
        rows = sb.table("self_monitoring").select("app_name,repo,finding_state").execute().data or []
        for r in rows:
            repo = (r.get("repo") or "").strip()
            state = dict(r.get("finding_state") or {})
            watch = dict(state.get("watch") or {})
            if not repo or not watch:
                continue                      # no daily check has built a status yet: nothing to refresh
            last = deepwatch.last_deep_scan(sb, repo)
            if not isinstance(last, dict):
                continue                      # none found, or the lookup failed: say nothing new
            shown = watch.get("last_deep")
            if isinstance(shown, dict) and shown.get("id") == last.get("id"):
                continue                      # already up to date
            rec = deepwatch.evaluate(now, last, {"commits": 0, "files": []}, [], watch.get("recommend"))
            watch["last_deep"] = last
            watch["change"] = {"commits": 0, "categories": []}
            watch["recommend"] = rec
            watch["refreshed_at"] = now.isoformat()
            state["watch"] = watch
            sb.table("self_monitoring").update({"finding_state": state}).eq("app_name", r["app_name"]).execute()
            done += 1
    except Exception as e:
        print(f"[self-monitor] deep scan status refresh skipped: {type(e).__name__}: {e}", flush=True)
    return done


def maybe_tick():
    """Call on a normal page load. Does nothing (one cheap query) unless an
    app is actually overdue. Never raises — a failure here must never break
    the homepage for a real visitor."""
    sb = _sb()
    if sb is None:
        return
    refresh_deep_status()
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


def _analysis_version():
    try:
        fn = _deps.get("analysis_version")
        return str(fn()) if fn else ""
    except Exception:
        return ""


def _parse_iso(text):
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except Exception:
        return None


def code_unchanged(row, head_sha, version, now=None):
    """True ONLY when it is certain that nothing needs scanning: the newest commit is the one the last successful scan read, that scan
    used the same scan rules, it was under RESCAN_UNCHANGED_DAYS ago, and the app has no recorded error. Any doubt gives False."""
    try:
        if not head_sha or not row or row.get("last_error") or not row.get("score"):
            return False
        scanned = (row.get("finding_state") or {}).get("scanned")
        if not isinstance(scanned, dict) or scanned.get("sha") != head_sha:
            return False
        if (scanned.get("version") or "") != (version or ""):
            return False
        at = _parse_iso(scanned.get("at"))
        if at is None:
            return False
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        age = (now or datetime.now(timezone.utc)) - at
        return timedelta(0) <= age <= timedelta(days=RESCAN_UNCHANGED_DAYS)
    except Exception:
        return False


def _record_scanned(sb, app_name, head_sha):
    """Remember which commit this scan read and when, in finding_state. Best effort: if it fails, the next check just scans again."""
    try:
        res = sb.table("self_monitoring").select("finding_state").eq("app_name", app_name).execute()
        state = dict((res.data[0].get("finding_state") if res.data else None) or {})
        state["scanned"] = {"sha": head_sha, "at": datetime.now(timezone.utc).isoformat(), "version": _analysis_version()}
        sb.table("self_monitoring").update({"finding_state": state}).eq("app_name", app_name).execute()
    except Exception as e:
        print(f"[self-monitor] could not record the scanned commit for {app_name}: {type(e).__name__}: {e}", flush=True)


def _run_scan(app_name, repo):
    """One check of one of our own apps. Its AI use is counted under 'monitor' (verilay_usage.py), not as a visitor's scan."""
    with usage.attribute("monitor"):
        _scan_body(app_name, repo)


def _scan_body(app_name, repo):
    sb = _sb()
    try:
        owner, _, name = repo.partition("/")
        head_sha = None
        try:
            head = deepwatch.head_info(owner, name, _deps["github_token"]())
            head_sha = head.get("sha") if isinstance(head, dict) else None
        except Exception:
            head_sha = None
        try:
            _rows = sb.table("self_monitoring").select("score,last_error,finding_state").eq("app_name", app_name).execute().data or []
        except Exception:
            _rows = []
        if _rows and code_unchanged(_rows[0], head_sha, _analysis_version()):
            usage.scan_done("monitor_skipped")
            print(f"[self-monitor] {app_name}: code unchanged since the last scan, nothing to do", flush=True)
            return
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

        # Admin-only detail: WHICH issues are open / newly fixed. Best-effort and
        # after the counts above are already saved, so it can never cost a check.
        _track_findings(sb, app_name, _collect_findings(
            scan_findings, osv_vulns, s2.get("layers", []) + s3.get("layers", [])))

        # Should a deep scan be run? Decided from steady signals only (see verilay_deepwatch.py). Best effort:
        # it can never cost a check.
        _update_watch(sb, app_name, repo, scan_findings, osv_vulns, all_files)
        if not (getattr(osv_vulns, "coverage", None) or {}).get("incomplete"):
            _record_scanned(sb, app_name, head_sha)     # an unfinished dependency check must be tried again, not remembered as done
        usage.scan_done("monitor")

        # Alert Moses ONLY when critical count went UP (including the first
        # ever successful check finding any) — never on a routine unchanged
        # or improved check. Best-effort: send_self_monitor_alert() never
        # raises, so a failed/unconfigured email can't affect the scan result
        # that was already saved above.
        prev_critical = prev_row.get("critical")
        if crit > (prev_critical or 0):
            notify.send_self_monitor_alert(app_name, repo, score, crit, warn, prev_critical)
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"[:500]
        print(f"[self-monitor] scan failed for {app_name}: {err_text}", flush=True)
        # maybe_tick() already marked this app "checked" (last_checked_at=now)
        # the moment it claimed the row, before this scan ran — so a FAILED
        # scan looks identical to a successful one and would otherwise sit
        # untried for the full CHECK_INTERVAL_HOURS. Back the timestamp off
        # so the next tick (traffic OR the scheduler, whichever comes first)
        # picks it up again shortly instead of waiting a full day. Best-effort
        # — if even this fails, worst case is the original wait, not a crash.
        # Also persist the actual error so it's visible from
        # /self-monitor-health without needing Railway log access — Supabase's
        # own dashboard logs are a different system and never show these
        # application-level prints.
        try:
            retry_at = datetime.now(timezone.utc) - timedelta(hours=CHECK_INTERVAL_HOURS) + timedelta(hours=1)
            sb.table("self_monitoring").update(
                {"last_checked_at": retry_at.isoformat(), "last_error": err_text}
            ).eq("app_name", app_name).execute()
        except Exception:
            pass


def _norm_title(title):
    """Lower-cased words only, so trivial punctuation/casing changes in an
    AI-written finding title don't make the same finding look 'fixed + new'."""
    return " ".join("".join(c.lower() if c.isalnum() else " " for c in (title or "")).split())


def _collect_findings(scan_findings, osv_vulns, layers):
    """Everything currently open on one app, as {stable_key: item}. Items hold a
    title and a location only -- never a secret's value (the scanner's preview
    is deliberately not copied) and never code.

    Secret-scan and dependency findings have stable identities. The AI layer
    findings are keyed by their normalised title, which is the best available
    but can drift if the model rewords one -- the admin page says so."""
    items = {}
    for f in scan_findings or []:
        if f.severity not in ("critical", "warning"):
            continue
        items[f"secret|{f.rule_id}|{f.file}"] = {
            "sev": f.severity, "title": f.name, "where": f.file, "src": "secret scan"}
    for v in osv_vulns or []:
        label = f"{v.package} {v.version_found}".strip()
        items[f"dep|{v.ecosystem}|{v.package}|{v.id}"] = {
            "sev": v.severity, "title": f"{label}: {v.summary or v.id}"[:160],
            "where": v.id + (f" (fix: {v.fixed_version})" if v.fixed_version else ""),
            "src": "dependency" + (" (dev only)" if v.is_dev else "")}
    for layer in layers or []:
        for f in layer.get("expert", {}).get("findings", []):
            sev = (f.get("severity") or "").lower()
            title = (f.get("title") or "").strip()
            if sev not in ("critical", "warning") or not title:
                continue
            items[f"ai|{sev}|{_norm_title(title)}"] = {
                "sev": sev, "title": title[:160], "where": (f.get("file") or "")[:120],
                "src": "AI analysis"}
    return items


def _track_findings(sb, app_name, current):
    """Compare this check's open issues with the previous check's and keep a
    running log of what disappeared. Stored in self_monitoring.finding_state
    (jsonb) -- see supabase_self_monitoring_findings.sql. Never raises: if the
    column has not been added yet it logs once per check and moves on.

    The first successful run only records a baseline (nothing to compare to),
    so fixes that happened before tracking started can't be named."""
    try:
        res = sb.table("self_monitoring").select("finding_state").eq("app_name", app_name).execute()
    except Exception as e:
        print(f"[self-monitor] finding detail skipped for {app_name} "
              f"(finding_state column missing?): {e}", flush=True)
        return
    try:
        now = datetime.now(timezone.utc).isoformat()
        prev = (res.data[0].get("finding_state") if res.data else None) or {}
        prev_open = prev.get("open")
        log = list(prev.get("resolved_log") or [])
        if prev_open is None:  # baseline run
            fixed, new = [], []
            baseline_at = now
        else:
            fixed = [dict(it, resolved_at=now) for k, it in prev_open.items() if k not in current]
            new = [it for k, it in current.items() if k not in prev_open]
            baseline_at = prev.get("baseline_at") or now
            log = (fixed + log)[:RESOLVED_LOG_MAX]
        state = {"open": current, "last_fixed": fixed, "last_new": new,
                 "resolved_log": log, "baseline_at": baseline_at, "updated_at": now}
        if prev.get("watch") is not None:
            state["watch"] = prev["watch"]      # owned by _update_watch(); never lose it here
        sb.table("self_monitoring").update({"finding_state": state}).eq("app_name", app_name).execute()
    except Exception as e:
        print(f"[self-monitor] finding detail failed for {app_name} (non-critical): {e}", flush=True)


def admin_detail_html(rows):
    """Admin-only: per app, what was fixed, what is new and what is still open.
    Only ever call from a route already gated to Moses (/account's is_admin
    block) -- this names real open issues on his live apps."""
    e = _html.escape
    colour = {"critical": "#A32D2D", "high": "#A32D2D", "warning": "#B7791F",
              "moderate": "#B7791F", "low": "#6b6966"}

    def li(it, when=None):
        sev = (it.get("sev") or "").lower()
        tail = f' <span class="note">&middot; {e(it.get("where") or "")}</span>' if it.get("where") else ""
        tail += f' <span class="note">&middot; {e(it.get("src") or "")}</span>'
        if when:
            tail += f' <span class="note">&middot; fixed {e(_format_checked_at(when) or "")}</span>'
        return (f'<li style="margin:.25rem 0"><span style="font-weight:700;color:{colour.get(sev, "#1a1917")}">'
                f'{e(sev.upper())}</span> {e(it.get("title") or "")}{tail}</li>')

    def section(title, items, when=False, cap=60, open_=False):
        if not items:
            return f'<p class="note" style="margin:.4rem 0">{e(title)}: none</p>'
        shown = "".join(li(i, i.get("resolved_at") if when else None) for i in items[:cap])
        more = f'<li class="note">...and {len(items) - cap} more</li>' if len(items) > cap else ""
        return (f'<details{" open" if open_ else ""} style="margin:.5rem 0"><summary style="cursor:pointer;'
                f'font-weight:600;font-size:13px">{e(title)} ({len(items)})</summary>'
                f'<ul style="margin:.4rem 0 .4rem 1.1rem;padding:0;font-size:13px">{shown}{more}</ul></details>')

    blocks = []
    for r in rows:
        name = e(r.get("app_name") or r.get("repo") or "app")
        st = r.get("finding_state")
        watch_block = watch_html(r)
        if not st:
            blocks.append(f'<p class="note" style="margin:.5rem 0"><strong>{name}</strong>: issue detail starts '
                          f'at the next check (counts above are unaffected).</p>')
            continue
        fixed, new = st.get("last_fixed") or [], st.get("last_new") or []
        log, open_items = st.get("resolved_log") or [], list((st.get("open") or {}).values())
        order = {"critical": 0, "high": 1, "warning": 2, "moderate": 3, "low": 4}
        open_items.sort(key=lambda i: order.get((i.get("sev") or "").lower(), 9))
        # The homepage badge counts only named, recorded fixes (public_resolved). When the TOTALS dropped but
        # nothing named disappeared, say why instead of leaving a silent 0.
        pc, pw = r.get("prev_critical"), r.get("prev_warnings")
        delta = None
        if pc is not None and pw is not None and r.get("critical") is not None:
            delta = (pc + pw) - ((r.get("critical") or 0) + (r.get("warnings") or 0))
        count_note = ""
        if delta and delta > 0 and not fixed:
            count_note = (f'<p class="note" style="margin:.4rem 0;background:#F1EFE8;border-radius:6px;padding:.4rem .6rem">'
                          f'The totals dropped by {delta} since the previous check, but none of the tracked issues '
                          f'disappeared, so the homepage badge shows nothing resolved. Either tracking only began at '
                          f'this check (the first check after setup records a baseline and cannot name earlier '
                          f'fixes), or the AI worded a finding differently. AI-written findings can vary between '
                          f'runs, so a lower total is not always a real fix.</p>')
        _rec = ((st.get("watch") or {}).get("recommend") or {}) if isinstance(st, dict) else {}
        head = (f'<strong>{"&#128276; " if _rec.get("active") else ""}{name}</strong> &mdash; fixed last check: {len(fixed)} &middot; '
                f'new: {len(new)} &middot; fixed since tracking: {len(log)} &middot; open: {len(open_items)}'
                + (f' &middot; totals {"-" if delta > 0 else "+"}{abs(delta)}' if delta else ""))
        base = _format_checked_at(st.get("baseline_at")) or ""
        blocks.append(
            f'<details class="mon-detail" style="margin:.6rem 0;border:0.5px solid #e8e6e0;border-radius:8px;padding:.5rem .8rem">'
            f'<summary style="cursor:pointer;font-size:14px">{head}</summary>'
            + count_note
            + section("Fixed since the previous check", fixed, when=True, open_=bool(fixed))
            + section("New since the previous check", new, open_=bool(new))
            + section("Fixed history (newest first)", log, when=True)
            + section("Still open", open_items)
            + f'<p class="note" style="margin:.5rem 0 0">Tracking began {e(base)}; fixes before that cannot be named. '
              f'AI-analysis items are matched by title, so a reworded finding can show as one fixed + one new.</p>'
            + '</details>')
        blocks.append(watch_block)
    return ('<div style="margin-top:1rem"><div style="font-size:12px;font-weight:600;color:#6b6966;'
            'text-transform:uppercase;letter-spacing:.03em;margin-bottom:.25rem">What changed</div>'
            + "".join(blocks) + '</div>')


# ── Deep scan recommendation (2026-10-13) ────────────────────────────────────

def _serious_keys(scan_findings, osv_vulns, authz_findings):
    """{stable_key: short title} of SERIOUS findings from the fixed rules only. The AI sample is left out on
    purpose: its findings vary between runs and would make the recommendation flicker."""
    out = {}
    for f in scan_findings or []:
        if f.severity == "critical":
            out[f"secret|{f.rule_id}|{f.file}"] = f"Exposed key: {f.name}"[:100]
    for v in osv_vulns or []:
        if v.severity in ("critical", "high") and not v.is_dev:
            out[f"dep|{v.ecosystem}|{v.package}|{v.id}"] = f"{v.package} {v.version_found}: vulnerable"[:100]
    for f in authz_findings or []:
        if f.level == "definite":
            out[f"authz|{f.rule_id}|{f.subject}"] = f.title[:100]
    return out


def _update_watch(sb, app_name, repo, scan_findings, osv_vulns, all_files):
    """Work out whether a deep scan is recommended, store it in finding_state["watch"] and email the admin when a
    recommendation newly appears. Never raises."""
    try:
        now = datetime.now(timezone.utc)
        owner, _, name = repo.partition("/")
        token = _deps["github_token"]()
        authz = []
        if _deps.get("authz_scan_repo"):
            try:
                authz = _deps["authz_scan_repo"](all_files)
            except Exception:
                authz = []
        keys = _serious_keys(scan_findings, osv_vulns, authz)

        res = sb.table("self_monitoring").select("finding_state").eq("app_name", app_name).execute()
        state = dict((res.data[0].get("finding_state") if res.data else None) or {})
        prev_watch = dict(state.get("watch") or {})
        prev_det = prev_watch.get("det")
        # First run only records a baseline: nothing can be "new" yet.
        new_titles = [] if prev_det is None else [t for k, t in keys.items() if k not in prev_det]

        last = deepwatch.last_deep_scan(sb, repo)
        head = deepwatch.head_info(owner, name, token)
        change = None
        if isinstance(last, dict) and head:
            base = last.get("sha")
            if not base:      # an older deep scan did not record its commit: use the commit current at that time
                before = deepwatch.sha_before(owner, name, token, last.get("created_at"))
                base = before["sha"] if before else None
            if base:
                change = deepwatch.compare(owner, name, token, base, head["sha"])

        rec = deepwatch.evaluate(now, last, change, new_titles, prev_watch.get("recommend"))
        cats = {}
        if change:
            cats, _n = deepwatch.categorise(change.get("files"))
        watch = {
            "checked_at": now.isoformat(), "det": keys, "head": head,
            "last_deep": last if isinstance(last, dict) else (None if last is None else "unknown"),
            "change": ({"commits": change.get("commits"), "categories": sorted(cats)} if change else None),
            "recommend": rec,
        }
        if deepwatch.should_email(rec):
            owner_repo = f"{owner}/{name}"
            link = f"https://verilay.dev/deep/{owner_repo.lower()}"
            last_txt = ""
            if isinstance(last, dict):
                last_txt = f'{_format_checked_at(last.get("created_at")) or ""} (grade {last.get("grade") or "?"})'
            if notify.send_deep_scan_recommendation(app_name, repo, [r["text"] for r in rec["reasons"]],
                                                    rec.get("new_serious"), last_txt, link):
                rec["emailed_signature"] = rec["signature"]
        state["watch"] = watch
        sb.table("self_monitoring").update({"finding_state": state}).eq("app_name", app_name).execute()
    except Exception as e:
        print(f"[self-monitor] deep scan recommendation skipped for {app_name}: {type(e).__name__}: {e}", flush=True)


def watch_html(r):
    """Admin only: the deep scan status line for one monitored app, with the one-click button when recommended."""
    e = _html.escape
    st = r.get("finding_state") or {}
    w = st.get("watch") if isinstance(st, dict) else None
    if not w:
        return ""
    rec = w.get("recommend") or {}
    last = w.get("last_deep")
    repo = (r.get("repo") or "").strip().lower()
    last_txt = ("No deep scan yet" if last is None else "Last deep scan: unknown (could not look it up)" if last == "unknown" else
                f'Last deep scan: {e(_format_checked_at(last.get("created_at")) or "")}'
                + (f' &middot; grade {e(last.get("grade") or "?")}' if last.get("grade") else "")
                + (f' &middot; <a href="/report/{e(str(last.get("id")))}" target="_blank" rel="noopener">report</a>' if last.get("id") else ""))
    nm = e(r.get("app_name") or r.get("repo") or "this app")
    ch = w.get("change") or {}
    ch_txt = (f' &middot; {int(ch.get("commits") or 0)} change(s) since' if ch and ch.get("commits") is not None else "")
    if not rec.get("active"):
        return (f'<p class="note" style="margin:.2rem 0 .9rem .8rem">&#10003; <strong>{nm}</strong> &middot; Deep scan not needed right now &middot; {last_txt}{ch_txt}</p>')
    items = "".join(f'<li style="margin:.2rem 0">{e(x.get("text", ""))}</li>' for x in rec.get("reasons") or [])
    titles = rec.get("new_serious") or []
    tl = ("<div class=\"note\" style=\"margin-top:.3rem\">" + "; ".join(e(t) for t in titles[:5]) + "</div>") if titles else ""
    button = (f'<form method="POST" action="/deep/{e(repo)}/start" style="margin:.5rem 0 0">'
              f'<button type="submit" style="font-size:13px;padding:6px 14px;border-radius:20px;border:0;background:#534AB7;'
              f'color:#fff;cursor:pointer">Run deep scan</button></form>') if "/" in repo else ""
    return (f'<div style="margin:.2rem 0 .9rem;padding:.6rem .8rem;border:0.5px solid #EF9F27;border-radius:8px;background:#FEF3C7">'
            f'<div style="font-weight:700;font-size:13px;color:#92400E">&#128276; Deep scan recommended for {nm}</div>'
            f'<ul style="margin:.3rem 0 0 1.1rem;padding:0;font-size:13px">{items}</ul>{tl}'
            f'<div class="note" style="margin-top:.3rem">{last_txt}{ch_txt}</div>{button}</div>')


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
        "check_interval_hours": CHECK_INTERVAL_HOURS,
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


def admin_summary():
    """Full detail, including raw critical/warning COUNTS — unlike
    health_data() (used by the admin-only /self-monitor-health endpoint), this
    deliberately breaks the "never show real counts publicly" rule the rest
    of this module follows. Only ever call this from a route already gated
    to Moses himself (e.g. /account's is_admin check) — never from a public
    or customer-facing route."""
    sb = _sb()
    if sb is None:
        return []
    try:
        res = sb.table("self_monitoring").select("*").order("app_name").execute()
        rows = res.data or []
    except Exception as e:
        print(f"[self-monitor] admin_summary read failed: {e}", flush=True)
        return []
    for r in rows:
        # "Last checked" for the admin means the last time a real scan happened, not the last time we looked and found no change.
        try:
            real = ((r.get("finding_state") or {}).get("scanned") or {}).get("at")
            if real:
                r["looked_at"] = r.get("last_checked_at")
                r["last_checked_at"] = real
        except Exception:
            pass
    return rows


def _humanize_ago(iso_str):
    """'3 hours ago' / 'less than an hour ago'. Deliberately caps out around a
    day — CHECK_INTERVAL_HOURS keeps every real timestamp under ~24h, so this
    never needs to handle (and never risks displaying) a multi-day figure.
    Public-facing (the badge) — use _humanize_ago_full() for an admin view
    that should honestly show a stale app instead of hiding how stale."""
    if not iso_str:
        return None
    try:
        checked_at = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    hours = (datetime.now(timezone.utc) - checked_at).total_seconds() / 3600
    if hours < 1:
        return "less than an hour ago"
    h = int(hours)
    return f"{h} hour{'s' if h != 1 else ''} ago"


def _humanize_ago_full(iso_str):
    """Same idea as _humanize_ago() but scales to days — for the admin-only
    /account view, where a genuinely overdue app (e.g. stuck on a repeated
    failure) should show honestly as "6 days ago", not be hidden the way the
    public badge deliberately bounds its figure to under a day."""
    if not iso_str:
        return None
    try:
        checked_at = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    hours = (datetime.now(timezone.utc) - checked_at).total_seconds() / 3600
    if hours < 1:
        return "less than an hour ago"
    if hours < 24:
        h = int(hours)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    d = int(hours // 24)
    return f"{d} day{'s' if d != 1 else ''} ago"


def _format_checked_at(iso_str):
    """'15 Sep 2026, 03:07 UTC' — absolute timestamp for the admin table,
    same %d %b %Y %H:%M convention used for report generated_at elsewhere."""
    if not iso_str:
        return None
    try:
        checked_at = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return checked_at.strftime("%d %b %Y, %H:%M UTC")


def public_resolved(row):
    """How many issues the public badge may call 'resolved since the last check' for one app.

    Only issues we actually recorded as gone count (finding_state.last_fixed), never a drop in
    the TOTAL counts, which can come from the AI wording a finding differently between runs.
    Secret-scan and dependency fixes are exact. AI-written findings are matched by title, so a
    reworded finding appears as one 'fixed' plus one 'new' in the same check; those cancel out
    (net fixed = fixed - new, never below zero). No tracking data yet means 0."""
    st = row.get("finding_state") or {}
    fixed = st.get("last_fixed") or []
    new = st.get("last_new") or []
    exact = sum(1 for i in fixed if i.get("src") != "AI analysis")
    ai_fixed = len(fixed) - exact
    ai_new = sum(1 for i in new if i.get("src") == "AI analysis")
    return exact + max(0, ai_fixed - ai_new)


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
    safe to expose, only how visible the honest version of it is.

    The "last checked" figure (re-added 2026-09-15) was removed on 2026-08-19
    because it could grow stale on a quiet traffic day — see this module's
    docstring. It's back now because start_scheduler() guarantees every row
    is checked at least every CHECK_INTERVAL_HOURS regardless of traffic, so
    the worst case is "~23 hours ago," not the multi-day figure that
    prompted removing it the first time."""
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

    # Named, recorded fixes only (see public_resolved). Until fixes are recorded this stays 0 and the
    # badge says nothing about resolved issues, by choice: an accurate claim beats a bigger number.
    resolved = sum(public_resolved(r) for r in checked)

    if total_open == 0:
        detail = "0 issues found — all clear at the latest check"
    elif resolved > 0:
        detail = f"{resolved} issue{'s' if resolved != 1 else ''} resolved since the last check"
    else:
        detail = ""

    detail_html = f" &nbsp;·&nbsp; {detail}" if detail else ""

    # No "last checked" time on the public badge (Moses, 2026-10-22): apps are re-scanned when their code changes, so a time
    # would only show how long ago the code last changed.

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
