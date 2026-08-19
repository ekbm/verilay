"""
verilay_notify.py — transactional email for completed deep scans.

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

© 2026 Moses Ekbote.
"""

import os
import smtplib
from email.mime.text import MIMEText

ZEPTOMAIL_TOKEN = os.getenv("ZEPTOMAIL_TOKEN", "").strip()
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
