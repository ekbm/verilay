"""
verilay_notify.py — transactional email for completed deep scans, and an
alert email for Moses when continuous self-monitoring finds something new.

Sign-in emails go through Supabase Auth's own magic-link flow (see
verilay_accounts.py's send_login_email) and never touch this module —
Supabase Auth has no equivalent for "your deep scan is done," so this
sends that one email directly. Reuses the same ZeptoMail SMTP relay
Supabase Auth is configured with (smtp.zeptomail.com, username the literal
string "emailapikey") — Verilay's backend has no other route to Supabase's
internal SMTP settings, so this needs its own copy of the Send Mail Token
as its own env var.

Best-effort only. A failed notification must never fail the scan job or
lose the report — the report is already saved by the time this runs.

The self-monitor alert recipient reuses ADMIN_EMAILS (verilay_billing.py's
existing env var for the admin deep-scan bypass) rather than a new env var —
it already holds Moses's own email, is already set on Railway, and verilay
is a PUBLIC repo so that address must never sit in source either way. Reads
it directly rather than importing verilay_billing, since this module must
stay usable even when the paid path (_HAS_PAYWALL) fails to import.

© 2026 Moses Ekbote.
"""

import os
import smtplib
from email.mime.text import MIMEText

ZEPTOMAIL_TOKEN = os.getenv("ZEPTOMAIL_TOKEN", "").strip()
_ADMIN_EMAILS = [e.strip() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]
SELF_MONITOR_ALERT_EMAIL = _ADMIN_EMAILS[0] if _ADMIN_EMAILS else ""
FROM_ADDRESS = "noreply@verilay.dev"
# Where a new "register interest in monitoring" sign-up is announced. moses@verilay.dev is already the
# public contact address on the site; MONITORING_INTEREST_NOTIFY_EMAIL overrides it without a deploy.
MONITORING_INTEREST_NOTIFY_EMAIL = (os.getenv("MONITORING_INTEREST_NOTIFY_EMAIL", "moses@verilay.dev") or "").strip()


def configured():
    return bool(ZEPTOMAIL_TOKEN)


def send_scan_complete_email(email, repo, report_url):
    """Best-effort — returns True/False, never raises."""
    if not configured():
        print("[notify] ZEPTOMAIL_TOKEN not set — skipping completion email", flush=True)
        return False

    body = (
        f"Your Verilay deep scan of {repo} is done.\n\n"
        f"View your report: {report_url}\n\n"
        f"You can re-scan this same app as many times as you like for the "
        f"next 30 days — sign in anytime to see your reports.\n\n"
        f"— Verilay"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"Your deep scan of {repo} is ready"
    msg["From"] = FROM_ADDRESS
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [email], msg.as_string())
        print(f"[notify] Completion email sent to {email} for {repo}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Completion email failed for {email}: {e}", flush=True)
        return False


def send_report_email(email, repo, headline, report_url, save_link=None, separate_save=False):
    """ "Email me this report" (28 Oct 2026): the report link, and (for a report not yet in an account) a one-click
    link that signs them in and saves it. Best-effort: returns True/False, never raises."""
    if not configured():
        print("[notify] ZEPTOMAIL_TOKEN not set — skipping report email", flush=True)
        return False
    lines = [f"Your Verilay report for {repo}", "", headline, "", f"See your report: {report_url}", ""]
    if save_link:
        lines += ["Save it to your account so it is kept for good (free reports are deleted after 90 days).",
                  "No password needed, just click:", "", f"Save my report: {save_link}", "",
                  "Didn't ask for this? Ignore this email and nothing is saved.", ""]
    elif separate_save:
        lines += ["To keep it for good, click the sign-in link we sent in a separate email.", ""]
    lines += ["— Verilay", "https://verilay.dev"]
    msg = MIMEText("\n".join(lines))
    msg["Subject"] = f"Your Verilay report for {repo}"
    msg["From"] = FROM_ADDRESS
    msg["To"] = email
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [email], msg.as_string())
        print(f"[notify] Report email sent to {email} for {repo}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Report email failed for {email}: {e}", flush=True)
        return False


def send_self_monitor_alert(app_name, repo, score, critical, warnings, prev_critical):
    """Best-effort — returns True/False, never raises.

    Fires ONLY when a monitored app's critical count goes UP — including its
    first-ever successful check finding any critical issues at all — never on
    every routine check. That's a deliberate call by verilay_self_monitor.py's
    caller, not this function: a daily "still fine" email would train Moses
    to ignore these, the same way a "checked X days ago" figure that always
    grows trained him to distrust the self-monitor badge before. Silently
    does nothing if ZEPTOMAIL_TOKEN or SELF_MONITOR_ALERT_EMAIL isn't set."""
    if not configured() or not SELF_MONITOR_ALERT_EMAIL:
        return False

    delta_line = (
        f"{critical} critical, {warnings} warnings — up from {prev_critical} critical last check"
        if prev_critical else
        f"{critical} critical, {warnings} warnings"
    )
    body = (
        f"Verilay's continuous monitoring found new critical issues in {app_name}.\n\n"
        f"Repo: {repo}\n"
        f"Grade: {score}  ({delta_line})\n\n"
        f"Go to verilay.dev and paste this repo's URL to see the specific findings "
        f"and how to fix each one.\n\n"
        f"— Verilay"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"New issues found in {app_name} ({score})"
    msg["From"] = FROM_ADDRESS
    msg["To"] = SELF_MONITOR_ALERT_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [SELF_MONITOR_ALERT_EMAIL], msg.as_string())
        print(f"[notify] Self-monitor alert sent for {app_name}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Self-monitor alert failed for {app_name}: {e}", flush=True)
        return False


def send_live_watch_alert(app_name, url, problems):
    """Best-effort, returns True/False, never raises. Sent to the admin when a protection on a monitored app's LIVE site gets worse
    (a header gone, http no longer sent to https, a certificate close to expiry). Never a daily "all fine"; a problem that stays is
    mentioned again after a week (see verilay_livewatch.py)."""
    if not configured() or not SELF_MONITOR_ALERT_EMAIL or not problems:
        return False
    lines = "\n".join(f"  - {_one_line(p, 160)}" for p in problems)
    body = (
        f"Something changed on the live site of {app_name} ({_one_line(url, 120)}):\n\n{lines}\n\n"
        f"This is separate from the code check: it is what the running site actually sends to a browser. "
        f"You will not get this email every day. If a problem stays, you get a reminder after a week.\n\n"
        f"- Verilay"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"Verilay: a protection on {_one_line(app_name, 60)} changed"
    msg["From"] = FROM_ADDRESS
    msg["To"] = SELF_MONITOR_ALERT_EMAIL
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [SELF_MONITOR_ALERT_EMAIL], msg.as_string())
        print(f"[notify] Live-site alert sent for {app_name}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Live-site alert failed for {app_name}: {e}", flush=True)
        return False


def send_admin_alert(subject, lines):
    """A short "something unusual happened" email to the admin (27 Oct 2026: a suspicious upload, free scans paused by
    the daily budget). Best-effort, returns True/False, never raises. The caller limits how often it is sent."""
    if not configured() or not SELF_MONITOR_ALERT_EMAIL:
        return False
    body = ("\n".join(f"  - {_one_line(x, 240)}" for x in (lines or [])) + "\n\nNothing was shared with the visitor beyond the "
            "usual message. You can see recent scans on /admin/scans.\n\n- Verilay")
    msg = MIMEText(body)
    msg["Subject"] = "Verilay alert: " + _one_line(subject, 90)
    msg["From"] = FROM_ADDRESS
    msg["To"] = SELF_MONITOR_ALERT_EMAIL
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [SELF_MONITOR_ALERT_EMAIL], msg.as_string())
        print(f"[notify] admin alert sent: {_one_line(subject, 90)}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] admin alert failed: {e}", flush=True)
        return False


def _one_line(s, limit=200):
    """Header-safe: no line breaks, capped."""
    return " ".join(str(s or "").split())[:limit]


def send_deep_scan_recommendation(app_name, repo, reasons, titles=None, last_deep="", link=""):
    """Best-effort, returns True/False, never raises. Sent to the admin when monitoring decides a deep scan is
    worth running. Only when a recommendation NEWLY appears or its reasons change: never a daily "all fine"."""
    if not configured() or not SELF_MONITOR_ALERT_EMAIL:
        return False
    lines = "\n".join(f"  - {r}" for r in reasons)
    extra = ("\nNew serious findings (titles only):\n" + "\n".join(f"  - {t}" for t in (titles or [])[:5]) + "\n") if titles else ""
    body = (
        f"Verilay's monitoring thinks a deep scan of {app_name} is worth running.\n\n"
        f"Why:\n{lines}\n{extra}\n"
        f"{('Last deep scan: ' + last_deep + chr(10) + chr(10)) if last_deep else ''}"
        f"Run it here (you must be signed in): {link}\n\n"
        f"You will get another email only if the reasons change. Once you run a deep scan, this clears by itself.\n\n"
        f"- Verilay"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"Verilay: a deep scan of {app_name} is recommended"
    msg["From"] = FROM_ADDRESS
    msg["To"] = SELF_MONITOR_ALERT_EMAIL
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [SELF_MONITOR_ALERT_EMAIL], msg.as_string())
        print(f"[notify] Deep scan recommendation sent for {app_name}", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Deep scan recommendation failed for {app_name}: {e}", flush=True)
        return False


def send_private_repo_interest_alert(email, answers, notes=""):
    """Tell Moses someone registered interest in a way to connect a PRIVATE repository. Best-effort, returns True/False,
    never raises. `answers` is an ordered {question: answer} dict of already-readable text."""
    to = MONITORING_INTEREST_NOTIFY_EMAIL
    if not configured() or not to:
        print("[notify] ZEPTOMAIL_TOKEN or recipient not set, skipping private-repo interest alert", flush=True)
        return False
    lines = ["Someone registered interest in checking a private repository with Verilay.", "", f"Email: {_one_line(email, 254)}"]
    for question, answer in (answers or {}).items():
        lines.append(f"{_one_line(question, 80)}: {_one_line(answer, 160) or '(not answered)'}")
    if notes:
        lines += ["", "Notes:", str(notes)[:300]]
    lines += ["", "All sign-ups: verilay.dev/account (Private repo interest).", "", "— Verilay"]
    msg = MIMEText("\n".join(lines))
    msg["Subject"] = _one_line(f"New private-repo interest: {email}", 120)
    msg["From"] = FROM_ADDRESS
    msg["To"] = to
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [to], msg.as_string())
        return True
    except Exception as e:
        print(f"[notify] private-repo interest alert failed: {type(e).__name__}", flush=True)
        return False


def send_monitoring_interest_alert(email, repo, answers, notes=""):
    """Tell Moses someone registered interest in monitoring. Best-effort, returns True/False, never raises.
    `answers` is an ordered {question: answer} dict of already-readable text."""
    to = MONITORING_INTEREST_NOTIFY_EMAIL
    if not configured() or not to:
        print("[notify] ZEPTOMAIL_TOKEN or recipient not set, skipping monitoring-interest alert", flush=True)
        return False
    lines = [f"Someone registered interest in Verilay monitoring.", "", f"Email: {_one_line(email, 254)}"]
    if repo:
        lines.append(f"Repository: {_one_line(repo, 120)}")
    for question, answer in (answers or {}).items():
        lines.append(f"{_one_line(question, 80)}: {_one_line(answer, 120) or '(not answered)'}")
    if notes:
        lines += ["", "Notes:", str(notes)[:300]]
    lines += ["", "All sign-ups: verilay.dev/account (Monitoring interest).", "", "— Verilay"]
    msg = MIMEText("\n".join(lines))
    msg["Subject"] = _one_line(f"New monitoring interest: {email}", 120)
    msg["From"] = FROM_ADDRESS
    msg["To"] = to
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [to], msg.as_string())
        print("[notify] Monitoring-interest alert sent", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Monitoring-interest alert failed: {e}", flush=True)
        return False


_STORY_ALERTS = []


def send_improvement_story_alert(report_id, story, repo=""):
    """Tell Moses someone answered "Went up a grade? Tell us what you changed." Best-effort, returns True/False, never
    raises. At most 20 of these emails per worker per hour; the answer itself is already stored on the report."""
    import time as _t
    to = MONITORING_INTEREST_NOTIFY_EMAIL
    if not configured() or not to:
        print("[notify] ZEPTOMAIL_TOKEN or recipient not set, skipping improvement-story alert", flush=True)
        return False
    now = _t.time()
    _STORY_ALERTS[:] = [x for x in _STORY_ALERTS if now - x < 3600]
    if len(_STORY_ALERTS) >= 20:
        print("[notify] improvement-story alert cap reached this hour; answer stored, no email sent", flush=True)
        return False
    _STORY_ALERTS.append(now)
    s = story or {}
    helped = {"yes": "Yes", "partly": "A bit", "no": "No", "unused": "Didn't use them"}.get(s.get("helped"), "(not answered)")
    lines = ["Someone answered the feedback question after a better Verilay scan.", "",
             f"Did the fix prompts help? {helped}",
             f"App: {_one_line(repo, 120) or '(no name)'}",
             f"Grade: {_one_line(s.get('grade_before') or 'n/a', 4)} -> {_one_line(s.get('grade_after') or 'n/a', 4)}"
             f" ({int(s.get('no_longer_found') or 0)} issues no longer found)",
             f"Email: {_one_line(s.get('email'), 254) or '(not given)'}",
             f"May be quoted (without their name): {'yes' if s.get('quote_ok') else 'no'}",
             f"Wants early access to fix sessions: {'yes' if s.get('early_access') else 'no'}",
             "", "What they think / what could be better:", str(s.get("opinion") or "(nothing written)")[:1000],
             "", "How they fixed it (optional):", str(s.get("changed") or "(not shared)")[:1000],
             "", f"Report: https://verilay.dev/report/{_one_line(report_id, 40)}", "", "— Verilay"]
    msg = MIMEText("\n".join(lines))
    msg["Subject"] = _one_line(f"Fix prompt feedback: {repo or 'a rescanned app'}", 120)
    msg["From"] = FROM_ADDRESS
    msg["To"] = to
    try:
        with smtplib.SMTP_SSL("smtp.zeptomail.com", 465, timeout=15) as server:
            server.login("emailapikey", ZEPTOMAIL_TOKEN)
            server.sendmail(FROM_ADDRESS, [to], msg.as_string())
        return True
    except Exception as e:
        print(f"[notify] improvement-story alert failed: {type(e).__name__}", flush=True)
        return False
