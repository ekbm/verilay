"""
verilay_deepscan.py — the paid deep-scan engine.

A job, not a stream (Decision 1 in DEEP-SCAN-DESIGN.md): reads far more files
than the free scan, splits them into batches, runs the same tuned layer-review
prompts per batch, then ONE synthesis pass merges the batches into a single
report (Decision 2a). This is the exact approach validated against real repos
in experiment_batching.py before being built as production code — same
prompts, same merge strategy, now wired to persist and to save into a report
the buyer can revisit.

Runs in a background thread so a buyer can close the tab; the progress page
polls for status and redirects to the normal /report/<id> page once done —
reusing that page's existing, already-tested rendering rather than building a
second one.

Kept dependency-injected (configure(), called once from app.py) rather than
importing app.py directly, to avoid a circular import — app.py imports this
module, so this module cannot import app.py back.

Job store is Supabase-backed (supabase_deepscan.sql) — Railway runs 4
separate Gunicorn worker processes, so an in-memory dict meant a buyer's
progress-poll could land on a different worker than the one running their
job and 404 at random. Falls back to an in-memory dict only when no
Supabase client is configured (local dev without credentials) — same
"in-memory fallback" pattern already used for reports and rate limiting
elsewhere in this codebase, not something production should ever rely on.

The synthesis prompt (PLATFORM AWARENESS + the merge/dedupe instructions)
is fetched from Supabase too, not hardcoded here. verilay is a PUBLIC repo,
and that prompt text — not the surrounding Python — is the actual tuned,
paid-tier IP. Fetched once per worker and cached; an edit in Supabase's
Table Editor takes effect on the next deploy/restart, not live.
"""
import threading
import time
import uuid
from datetime import datetime, timezone

MAX_DEEP_FILES = 150
BATCH_SIZE = 25
LAYER_NAMES_STEP2 = ["Auth", "Config", "Database"]
LAYER_NAMES_STEP3 = ["API", "Frontend", "Libraries"]
ALL_LAYERS = LAYER_NAMES_STEP2 + LAYER_NAMES_STEP3

# Injected by configure() from app.py — reuses the exact tuned prompts and
# file-selection logic already there rather than duplicating them.
_deps = {}


def configure(**kwargs):
    _deps.update(kwargs)


def _sb():
    """The Supabase client, if one was configured. None in local dev without
    credentials — every function below falls back to in-memory storage when
    this is None, same graceful-degradation pattern used elsewhere."""
    return _deps.get("supabase_client")


# ── Job store — Supabase primary, in-memory fallback ────────────────────────
_JOBS = {}
_JOBS_LOCK = threading.Lock()


def create_job(repo, purchase_id, user_id=None):
    """`purchase_id` must be a real `purchases.id` UUID or None — the column
    has that type in Supabase. The admin-bypass entitlement's synthetic id
    ("admin-bypass-<repo>") is NOT a UUID, so the caller passes None for it;
    passing the synthetic string here used to fail the Supabase insert with
    a type error on every admin-bypass scan, silently falling back to this
    process's own memory and making the job invisible to any other worker
    process. `user_id`, unlike purchase_id, is set for admin-bypass scans
    too (there's a real signed-in account either way) — it's what lets
    active_jobs_for_user() find a scan and show it back to whoever started
    it, regardless of which entitlement path they used."""
    job_id = uuid.uuid4().hex[:16]
    row = {
        "id": job_id, "repo": repo, "purchase_id": purchase_id, "user_id": user_id,
        "status": "queued", "progress": "Queued...",
        "report_id": None, "error": None,
    }
    sb = _sb()
    if sb is not None:
        try:
            sb.table("deepscan_jobs").insert(row).execute()
            return job_id
        except Exception as e:
            print(f"[deepscan] Supabase job insert failed, falling back to memory: {e}", flush=True)
    with _JOBS_LOCK:
        _JOBS[job_id] = {**row, "created_at": datetime.now(timezone.utc).isoformat()}
    return job_id


def get_job(job_id):
    sb = _sb()
    if sb is not None:
        try:
            res = sb.table("deepscan_jobs").select("*").eq("id", job_id).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            print(f"[deepscan] Supabase job read failed, checking memory: {e}", flush=True)
    with _JOBS_LOCK:
        return dict(_JOBS[job_id]) if job_id in _JOBS else None


def active_job_for_repo(repo):
    """The most recent still-running job for this exact repo, or None.

    Used to stop a second scan starting while one's already going — running
    two at once on the same repo does not make either finish faster, it
    just burns a second set of GitHub/Claude calls (and a second purchase
    scan-count) for a report that will likely just say the same thing."""
    sb = _sb()
    if sb is not None:
        try:
            res = (sb.table("deepscan_jobs").select("*").eq("repo", repo)
                     .in_("status", ["queued", "running"])
                     .order("created_at", desc=True).limit(1).execute())
            if res.data:
                return res.data[0]
        except Exception as e:
            print(f"[deepscan] Supabase active-job lookup failed, checking memory: {e}", flush=True)
    with _JOBS_LOCK:
        candidates = [dict(j) for j in _JOBS.values()
                      if j.get("repo") == repo and j.get("status") in ("queued", "running")]
        if candidates:
            return max(candidates, key=lambda j: j.get("created_at", ""))
    return None


def active_jobs_for_user(user_id):
    """Every still-running job this signed-in user started, newest first.

    Powers the "scan running" banner on /account — closing the progress
    tab used to lose your only way back to it; this is how /account can
    show it again and link straight back in."""
    if not user_id:
        return []
    sb = _sb()
    if sb is not None:
        try:
            res = (sb.table("deepscan_jobs").select("*").eq("user_id", user_id)
                     .in_("status", ["queued", "running"])
                     .order("created_at", desc=True).execute())
            return res.data or []
        except Exception as e:
            print(f"[deepscan] Supabase active-jobs-for-user lookup failed, checking memory: {e}", flush=True)
    with _JOBS_LOCK:
        jobs = [dict(j) for j in _JOBS.values()
                if j.get("user_id") == user_id and j.get("status") in ("queued", "running")]
        jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
        return jobs


def _update_job(job_id, **fields):
    sb = _sb()
    if sb is not None:
        try:
            sb.table("deepscan_jobs").update(fields).eq("id", job_id).execute()
            return
        except Exception as e:
            print(f"[deepscan] Supabase job update failed, falling back to memory: {e}", flush=True)
    with _JOBS_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(fields)


class _JobCancelled(Exception):
    """Raised internally by _check_cancelled() when a job has been marked
    cancelled since it started. Caught separately in _run_job() so it never
    gets relabeled as an "error" by the generic exception handler -- a
    cancelled scan is not a failure."""
    pass


def _check_cancelled(job_id):
    """Cooperative cancellation. The scan runs in a background thread and
    an in-flight Claude/GitHub call can't be interrupted mid-call, so this
    is checked BETWEEN _run_job()'s existing progress checkpoints instead
    (fetch, each analysis pass, dependency check, etc.) -- a cancel takes
    effect at the next checkpoint, not instantly."""
    job = get_job(job_id)
    if job and job.get("status") == "cancelled":
        raise _JobCancelled()


def cancel_job(job_id):
    """Marks a job cancelled if it's still queued/running. Returns True if
    it was actually still cancellable (False for a job that's already
    done/errored/cancelled -- nothing to do there)."""
    job = get_job(job_id)
    if not job or job.get("status") not in ("queued", "running"):
        return False
    _update_job(job_id, status="cancelled", progress="Cancelling...")
    return True


# ── Prompt store — Supabase only, no silent fallback ────────────────────────
# Unlike the job store, a missing prompt is a reason to STOP, not degrade —
# running a paid deep scan with a placeholder prompt would produce a worse
# report while still charging for it. Cached per-process since prompts
# change rarely (edited by hand in Supabase, not by users).
_prompt_cache = {}
_prompt_cache_lock = threading.Lock()


def _get_prompt(key):
    with _prompt_cache_lock:
        if key in _prompt_cache:
            return _prompt_cache[key]
    sb = _sb()
    if sb is None:
        raise RuntimeError(
            f"No Supabase client configured — cannot fetch deep-scan prompt '{key}'. "
            "Run supabase_deepscan.sql and supabase_deepscan_seed.sql, then confirm "
            "SUPABASE_URL/SUPABASE_KEY are set."
        )
    res = sb.table("deepscan_prompts").select("content").eq("key", key).execute()
    if not res.data:
        raise RuntimeError(
            f"Deep-scan prompt '{key}' not found in Supabase. Run "
            "supabase_deepscan_seed.sql to populate it."
        )
    content = res.data[0]["content"]
    with _prompt_cache_lock:
        _prompt_cache[key] = content
    return content


def start_job(job_id, user_id=None):
    """Kick off the scan in a background thread and return immediately —
    Decision 1: the buyer gets a page to poll, not a held-open connection.

    `user_id` is captured by the CALLER, in the original request, where
    Flask's session is actually available — a background thread has no
    request context, so save_report_data()'s usual "read the signed-in
    user from the session" fallback silently finds nobody and every deep
    scan report saves unlinked from any account, purchased or admin-
    bypassed alike. Passed through explicitly instead of relying on it."""
    t = threading.Thread(target=_run_job, args=(job_id, user_id), daemon=True)
    t.start()


def _build_findings_summary(report):
    """Per-finding summary for the advice-prompt step (analyse_step4) — same
    shape app.js's runPart2() builds client-side for the free tier (real
    finding titles/detail per layer, not just a bare layer status), so a
    paying customer's fix prompts are never thinner than what a free visitor
    already gets. Goes further where the paid tier legitimately can: real
    package names, versions, and CVE ids for Libraries findings, since that
    detail is what the $19 buys — Decision 6 only restricts what the FREE
    tier is shown, not what this prompt is allowed to say."""
    h = report.get("health", {})
    stack_names = ", ".join(s.get("name", "") for s in report.get("stack", [])[:5])
    lines = [
        f"Score: {h.get('score','')}, Critical: {h.get('critical',0)}, "
        f"Warnings: {h.get('warnings',0)}. Stack: {stack_names}.",
        "Findings by layer:",
    ]
    osv = report.get("osv_scan") or {}
    for layer in report.get("layers", []):
        name = layer.get("name", "")
        status = layer.get("status", "")
        if name == "Libraries":
            vulns = osv.get("vulnerabilities") or []
            if vulns:
                pkg_list = "; ".join(
                    f"{v.get('package','')}@{v.get('version_found','')} ({v.get('id','')})"
                    + (f" -> fix: {v['fixed_version']}" if v.get("fixed_version") else "")
                    for v in vulns
                )
                lines.append(f"- Libraries [{status}]: {pkg_list}")
            else:
                lines.append(f"- Libraries [{status}]: no known dependency vulnerabilities.")
            continue
        findings = [
            f for f in (layer.get("expert") or {}).get("findings", [])
            if f.get("title") and f.get("title") != "No issues found"
        ]
        if findings:
            detail = "; ".join(f"{f.get('title','')}: {f.get('detail','')}" for f in findings)
            lines.append(f"- {name} [{status}]: {detail}")
        else:
            lines.append(f"- {name} [{status}]: no issues found")
    return "\n".join(lines)


def _run_job(job_id, user_id=None):
    job = get_job(job_id)
    if not job:
        return
    repo = job["repo"]
    try:
        _update_job(job_id, status="running", progress="Fetching your repository...")
        owner, _, name = repo.partition("/")
        all_files = _deps["fetch_all_files_tarball"](owner, name, _deps["github_token"]())
        if not all_files:
            raise ValueError("Could not read any files from this repository.")

        selected_paths = _deps["smart_file_selection"](all_files, max_files=MAX_DEEP_FILES)
        files = {p: all_files[p][:_deps["max_file_chars"]] for p in selected_paths}
        batches = [dict(list(files.items())[i:i + BATCH_SIZE]) for i in range(0, len(files), BATCH_SIZE)]

        _update_job(job_id, progress=f"Reading {len(files)} files across {len(batches)} passes...")
        raw_results = []
        for i, batch in enumerate(batches, start=1):
            _check_cancelled(job_id)
            _update_job(job_id, progress=f"Analysing pass {i} of {len(batches)}...")
            s2 = _deps["analyse_step2"](batch, repo)
            s3 = _deps["analyse_step3"](batch, repo)
            raw_results.append({"batch": i, "step2": s2, "step3": s3})

        _check_cancelled(job_id)
        _update_job(job_id, progress="Checking every file for exposed keys...")
        scan_findings = _deps["scan_repo"](all_files)

        _check_cancelled(job_id)
        _update_job(job_id, progress="Checking dependencies against OSV.dev...")
        osv_vulns, osv_checked = _deps["check_dependencies"](all_files)

        _check_cancelled(job_id)
        _update_job(job_id, progress="Detecting your tech stack...")
        stack_result = _deps["analyse_step1"](files, list(all_files.keys()), repo, "github")

        _check_cancelled(job_id)
        _update_job(job_id, progress="Merging everything into one report...")
        scan_block = _deps["secret_to_prompt_block"](scan_findings, len(all_files))
        osv_block = _deps["osv_to_prompt_block"](osv_vulns, osv_checked)
        merged_layers = _synthesise(repo, raw_results, scan_block, osv_block)
        _fix_library_severities(merged_layers, osv_vulns)

        report = _assemble_report(
            repo=repo, stack_result=stack_result, merged_layers=merged_layers,
            scan_findings=scan_findings, files_scanned=len(all_files),
            osv_vulns=osv_vulns, osv_checked=osv_checked,
            files=files, files_total=len(all_files),
        )
        report["architecture_diagram"] = _deps["build_architecture_diagram"](
            report.get("stack", []), report.get("layers", [])
        )
        report["module_purpose_rows"] = _deps["build_module_purpose_rows_html"](
            report.get("stack", []), report.get("layers", [])
        )

        # "Advice Prompts" — copy-paste-into-Lovable/Replit fix guidance. The
        # free scan only generates these when a visitor clicks "Run Part 2";
        # a paying customer shouldn't need the extra click for something the
        # $19 is partly buying, so this always runs. Uses the SAME enriched
        # per-finding summary shape app.js's runPart2() builds for the free
        # tier (real finding titles/detail per layer, not just a bare status)
        # — a paying customer's fix prompts should never come out thinner
        # than what a free visitor already gets. Goes further where the paid
        # tier legitimately can: real package names/CVE ids for Libraries
        # findings, not just a count (Decision 6 only restricts what the
        # FREE tier is shown, not what this prompt can say).
        _check_cancelled(job_id)
        _update_job(job_id, progress="Writing advice prompts for your AI builder...")
        findings_summary = _build_findings_summary(report)
        # Same cap app.py's run_step4() applies to the free tier's version of
        # this call — a real multi-finding, multi-layer summary with exact
        # package/CVE detail can get long, and this is still one prompt with
        # a timeout budget, not unlimited context.
        if len(findings_summary) > 3000:
            findings_summary = findings_summary[:3000] + "..."
        try:
            step4 = _deps["analyse_step4"](repo, report.get("built_with", ""), findings_summary)
            report["top_fixes"] = step4.get("top_fixes", [])
            report["second_opinion"] = step4.get("second_opinion", {})
        except Exception as e:
            print(f"[deepscan] advice prompts failed, report still valid without them: {e}", flush=True)

        _check_cancelled(job_id)
        _update_job(job_id, progress="Saving your report...")
        report_id = _deps["save_report_data"](report, user_id)
        _deps["consume_scan"](job["purchase_id"])

        # The homepage's "N apps analysed so far" counter used to only move
        # for free-tier runs -- a deep scan is still an analysis of an app,
        # so it should count too, same best-effort, never-fail-the-job
        # pattern the free tier already uses.
        try:
            _deps["increment_analysis_count"](score=report.get("health", {}).get("score"), method="deep")
        except Exception as e:
            print(f"[deepscan] analysis-count increment skipped: {e}", flush=True)

        # Best-effort completion email — the buyer's told to close the tab and
        # come back, so without this the only way to know it's done is to
        # keep polling. Looks the email up fresh from purchases rather than
        # storing it on the job row, so this needs no schema change. Never
        # lets an email failure fail the job — the report is already saved.
        try:
            sb = _sb()
            email = None
            if sb is not None:
                purchase = sb.table("purchases").select("email").eq("id", job["purchase_id"]).execute()
                if purchase.data:
                    email = purchase.data[0].get("email")
            if email:
                report_url = f"{_deps['base_url']}/report/{report_id}"
                _deps["send_scan_complete_email"](email, repo, report_url)
        except Exception as e:
            print(f"[deepscan] completion email skipped: {e}", flush=True)

        _update_job(job_id, status="done", progress="Done", report_id=report_id)
    except _JobCancelled:
        # Status is already "cancelled" (set by cancel_job(), called from a
        # real user request) -- nothing more to do. No report saved, no
        # scan consumed, no completion email: as if it never ran.
        print(f"[deepscan] job {job_id} cancelled by user", flush=True)
    except Exception as e:
        print(f"[deepscan] job {job_id} failed: {e}", flush=True)
        _update_job(job_id, status="error", error=str(e))


def _synthesise(repo_name, raw_results, scan_block, osv_block):
    """The merge pass, Decision 2a — reads all batches' findings (not the raw
    files) and produces one deduped, severity-reconciled, narrative report.
    Same approach validated in experiment_batching.py.

    Also where the deterministic secret-scan and OSV.dev findings enter the
    narrative — fed here ONCE rather than into every batch call, since they
    cover the whole repo already and repeating them six times would just be
    six near-duplicate write-ups for the synthesis pass to dedupe for no
    benefit. Full detail this time (package names, CVE ids) since this is
    the paid tier — the free scan's teaser restriction doesn't apply here."""
    by_name = {name: [] for name in ALL_LAYERS}
    for entry in raw_results:
        for step_key in ("step2", "step3"):
            for layer in entry[step_key]["layers"]:
                tagged = dict(layer)
                tagged["_batch"] = entry["batch"]
                by_name[layer["name"]].append(tagged)

    sections = []
    for name in ALL_LAYERS:
        entries = by_name[name]
        real = [e for e in entries if not (
            len(e["expert"]["findings"]) == 1
            and e["expert"]["findings"][0]["title"] == "No issues found"
        )]
        sections.append(f"=== {name} layer — {len(entries)} batches, {len(real)} with findings ===")
        import json as _json
        sections.append(_json.dumps(real, indent=2))
    findings_block = "\n".join(sections)

    prompt = (
        f"You are Verilay, merging {len(raw_results)} independent batch reviews of "
        f"{repo_name} into ONE coherent report for a non-developer.\n\n"
        + scan_block + osv_block +
        _get_prompt("synthesis_instructions") + "\n\n"
        + _get_prompt("platform_awareness") + "\n"
        "WRITING FOR NON-TECHNICAL USERS: assume the reader has never coded. No unexplained "
        "jargon. Short warm paragraphs with everyday analogies, not clipped technical lines.\n\n"
        "RAW BATCH FINDINGS (JSON, one section per layer):\n" + findings_block + "\n\n"
        "Respond ONLY with flat key:value pairs, one per line, using EXACTLY this schema for all "
        "six layers — AUTH_*, CONFIG_*, DATABASE_*, API_*, FRONTEND_*, LIBRARIES_* — each with "
        "STATUS, SUMMARY, up to 5 F{n}_SEV/TITLE/DETAIL/FILE/WHY/PLAIN/IMPACT/ACTION, plus "
        "WHAT/ANALOGY/DOES/CONNECTS/CONCEPT/Q/A/QWHY. If a layer genuinely has no real findings "
        "after merging, say so — do not invent one."
    )
    # 20000 -- all 6 layers merged in one call (vs the free tier's 2 calls
    # of 3, each now budgeted 10000 tokens after live testing showed real
    # generation length varies a lot and repeatedly exceeded smaller
    # guesses, up to ~5470 tokens observed on just a 3-layer call).
    # Matching that per-layer rate for 6 layers in one call: a paying
    # customer's report should never come out worse than a free one
    # because this call ran short on tokens.
    merged_text = _deps["call_claude_text"](prompt, 20000)
    return _deps["parse_flat_response"](merged_text, ALL_LAYERS)


def _fix_library_severities(merged_layers, osv_vulns):
    """Deterministic correction, not a prompt tweak — testing this exact
    engine surfaced Claude writing an accurate, detailed description of real
    HIGH-severity vulnerabilities while tagging every one of them "passing".
    The narrative text was right; the severity field it's also responsible
    for was not, and that field is what colours the finding and (via
    _assemble_report's floor) sets the grade — so a wrong tag here is a
    trust problem, not a typo. Rather than hope a stronger prompt fixes it
    every time, match each finding's own text against the OSV data we
    already have and force the fields severity actually drives.

    Package-name substring matching against the finding's own title/detail
    is what's available post-synthesis (the merged finding no longer carries
    which batch or which OSV entry it came from) — imperfect if a package
    name were also an English word, acceptable given real package names in
    practice aren't."""
    if not osv_vulns:
        return merged_layers

    worst_per_package = {}
    for v in osv_vulns:
        bucket = "critical" if v.severity in ("critical", "high") else "warning"
        name = v.package.lower()
        if bucket == "critical" or worst_per_package.get(name) != "critical":
            worst_per_package[name] = bucket

    for layer in merged_layers.get("layers", []):
        if layer.get("name") != "Libraries":
            continue
        layer_worst = None
        for i, f in enumerate(layer.get("expert", {}).get("findings", [])):
            text = (f.get("title", "") + " " + f.get("detail", "")).lower()
            matched = next((pkg for pkg in worst_per_package if pkg in text), None)
            if not matched:
                continue
            correct_sev = worst_per_package[matched]
            f["severity"] = correct_sev
            learner_findings = layer.get("learner", {}).get("findings_plain", [])
            if i < len(learner_findings):
                learner_findings[i]["severity"] = correct_sev
            if correct_sev == "critical" or layer_worst != "critical":
                layer_worst = correct_sev
        if layer_worst:
            layer["status"] = layer_worst
    return merged_layers


def _assemble_report(repo, stack_result, merged_layers, scan_findings, files_scanned,
                      osv_vulns, osv_checked, files, files_total):
    """Shapes everything into the same report format the free scan's saved
    reports use, so /report/<id> and the account report history render this
    exactly like any other report — deep scans aren't a special case on the
    display side, only on how they were produced."""
    report = dict(stack_result)  # repo, summary, built_with, prod_ready, health (overwritten below)
    report["input_method"] = "github"
    report["is_deep_scan"] = True
    report["files_read"] = len(files)
    report["files_total"] = files_total
    report["file_breakdown"] = _deps["categorise_files"](list(files.keys()))
    report["files_analysed"] = sorted(files.keys())
    report["generated_at"] = datetime.now().strftime("%d %b %Y %H:%M")
    report["layers"] = merged_layers["layers"]

    # Same deterministic-floor pattern as the free scan (analyse_stream in
    # app.py): counted findings set the grade, scanners set a floor under it.
    crit = warn = passing = 0
    for layer in report["layers"]:
        for f in layer.get("expert", {}).get("findings", []):
            sev = (f.get("severity") or "").lower()
            if sev == "critical":
                crit += 1
            elif sev == "warning":
                warn += 1
            elif sev == "passing":
                passing += 1

    scan_critical = sum(1 for f in scan_findings if f.severity == "critical")
    scan_warning = sum(1 for f in scan_findings if f.severity == "warning")
    osv_critical, osv_warning = _deps["osv_severity_counts"](osv_vulns)

    crit = max(crit, scan_critical, osv_critical)
    warn = max(warn, scan_warning, osv_warning)

    report["health"] = {
        "critical": crit, "warnings": warn, "passing": passing,
        "score": _deps["grade_from_counts"](crit, warn),
    }
    report["secret_scan"] = _deps["secret_to_report_dict"](scan_findings, files_scanned)
    # Full detail here, unlike the free scan's teaser — this is what the $19 buys.
    report["osv_scan"] = _deps["osv_to_report_dict"](osv_vulns, osv_checked)
    return report
