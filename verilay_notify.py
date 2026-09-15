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
