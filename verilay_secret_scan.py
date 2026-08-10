"""
verilay_secret_scan.py — deterministic secret detection for Verilay.

Runs BEFORE Claude, over EVERY file in the repo — not the 25-file sample.
Costs nothing, never varies between runs, and cites exact file + line.

Stdlib only. No new dependencies (tarball fetch needs `requests`, which
Verilay already has).

Pattern set adapted from secret_scanner.py in alirezarezvani/claude-skills
(MIT Licence, Copyright (c) 2025 Alireza Rezvani), extended with
Supabase / Lovable / AI-builder detections that matter for Verilay's users.

Design rules, all deliberate:
  * Never flag a Supabase ANON key — that belongs in the frontend by design.
    DO flag a Supabase SERVICE_ROLE key, which looks almost identical but
    bypasses every row-level-security rule. We tell them apart by decoding
    the JWT payload. This is the single most dangerous thing a Lovable user
    can ship, and no generic scanner catches it.
  * Never flag process.env.X / import.meta.env.X / os.getenv() — those are
    references, not secrets.
  * Never flag placeholders (your_key_here, xxx, changeme, <...>).
  * .env.example is downgraded to info — it is meant to hold fake values.
  * Only ever return the first 6 characters of a matched secret.
"""

import base64
import json
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── What never gets scanned ────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".next", ".nuxt",
    "vendor", "venv", ".venv", "env", "coverage", ".cache", "tmp", "temp",
    ".pytest_cache", ".mypy_cache", "site-packages",
}

SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".mov", ".pdf", ".zip", ".tar", ".gz",
    ".lock", ".map", ".min.js", ".min.css", ".wasm",
)

# Files that legitimately contain fake secrets
EXAMPLE_FILES = (".env.example", ".env.sample", ".env.template", "env.example")

MAX_SCAN_BYTES = 2_000_000   # skip anything bigger; secrets don't live in 2MB files
MAX_LINE_LEN = 3_000         # skip minified megalines


# ── Findings ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str          # critical | warning | info
    file: str
    line: int
    preview: str           # first 6 chars only, never the whole secret
    plain: str             # plain-English one-liner for non-developers
    action: str            # what to do about it


@dataclass
class Rule:
    rule_id: str
    name: str
    regex: str
    severity: str
    plain: str
    action: str
    needs_entropy: bool = False
    compiled: Optional[re.Pattern] = field(default=None, repr=False)


# ── The pattern set ────────────────────────────────────────────────────────────

RULES: List[Rule] = [
    Rule("AWS001", "AWS Access Key ID",
         r"AKIA[0-9A-Z]{16}", "critical",
         "An Amazon Web Services access key is written directly into your code.",
         "Remove it from the code, move it to an environment variable, and rotate the key in the AWS console — assume it is compromised."),

    Rule("AWS002", "AWS Secret Access Key",
         r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", "critical",
         "An Amazon Web Services secret key is written directly into your code.",
         "Remove it, move it to an environment variable, and rotate the key in AWS immediately."),

    Rule("GCP001", "Google API Key",
         r"AIza[0-9A-Za-z\-_]{35}", "critical",
         "A Google API key is written directly into your code.",
         "Move it to an environment variable and restrict the key by domain in the Google Cloud console."),

    Rule("ANTH001", "Anthropic API Key",
         r"sk-ant-[A-Za-z0-9\-_]{20,}", "critical",
         "An Anthropic (Claude) API key is written directly into your code. Anyone who finds it can spend your credits.",
         "Delete it from the code, move it to an environment variable, and revoke the key at console.anthropic.com."),

    # Negative lookahead on "ant-": an Anthropic key (sk-ant-...) also satisfies
    # the generic sk- shape, and without this it gets reported twice under two names.
    Rule("OAI001", "OpenAI API Key",
         r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9\-_]{32,}", "critical",
         "An OpenAI API key is written directly into your code. Anyone who finds it can spend your credits.",
         "Delete it from the code, move it to an environment variable, and revoke the key at platform.openai.com."),

    Rule("STRIPE001", "Stripe Live Secret Key",
         r"sk_live_[0-9a-zA-Z]{20,}", "critical",
         "Your live Stripe key is in the code. Someone who finds it could issue refunds or read your customer payment records.",
         "Roll the key in your Stripe dashboard right now, then move the new one to an environment variable."),

    Rule("STRIPE002", "Stripe Test Secret Key",
         r"sk_test_[0-9a-zA-Z]{20,}", "warning",
         "A Stripe test key is in the code. It cannot move real money, but it should still not be committed.",
         "Move it to an environment variable so the same file does not later hold a live key."),

    Rule("GH001", "GitHub Token",
         r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}", "critical",
         "A GitHub access token is in your code. It could let someone read or change your repositories.",
         "Revoke it at github.com/settings/tokens and move the replacement to an environment variable."),

    Rule("GL001", "GitLab Token",
         r"glpat-[A-Za-z0-9\-_]{20,}", "critical",
         "A GitLab access token is in your code.",
         "Revoke it in GitLab and move the replacement to an environment variable."),

    Rule("SLACK001", "Slack Token",
         r"xox[baprs]-[A-Za-z0-9\-]{10,}", "critical",
         "A Slack token is in your code. It could let someone read or post in your workspace.",
         "Revoke it in your Slack app settings and move the replacement to an environment variable."),

    Rule("SG001", "SendGrid API Key",
         r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "critical",
         "A SendGrid key is in your code. Someone could send email that looks like it came from you.",
         "Revoke it in SendGrid and move the replacement to an environment variable."),

    Rule("TWL001", "Twilio Credential",
         r"\b(?:AC|SK)[0-9a-fA-F]{32}\b", "critical",
         "A Twilio credential is in your code. Someone could send SMS at your expense.",
         "Rotate it in the Twilio console and move the replacement to an environment variable."),

    Rule("PK001", "Private Key File",
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "critical",
         "A private key is stored in your code. This is the digital equivalent of committing your house keys.",
         "Delete the key from the repository, generate a new one, and never store private keys in code."),

    Rule("DB001", "Database Connection String With Password",
         r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@'\"]{6,}@", "critical",
         "A database address with its password is written into your code. Anyone who reads it can open your database directly.",
         "Move the whole connection string to an environment variable and change the database password."),

    Rule("JWT001", "JSON Web Token",
         r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "warning",
         "A login token is written into your code. These are meant to be short-lived, not stored.",
         "Remove it. If it belongs to a real account, sign that account out everywhere."),

    Rule("GEN001", "Generic Hardcoded Secret",
         r"(?i)(?:api[_-]?key|apikey|secret|auth[_-]?token|access[_-]?token|password|passwd)"
         r"\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{20,})[\"']", "warning",
         "Something that looks like a password or key is typed directly into your code.",
         "If it is a real secret, move it to an environment variable. If it is a placeholder, you can ignore this.",
         needs_entropy=True),
]

for _r in RULES:
    _r.compiled = re.compile(_r.regex)


# ── False-positive guards ──────────────────────────────────────────────────────

# A reference to a secret is not a secret.
ENV_REF = re.compile(
    r"process\.env|import\.meta\.env|os\.getenv|os\.environ|Deno\.env\.get|"
    r"ENV\[|getenv\(|config\(|secrets\.|\$\{?[A-Z_]+\}?$"
)

PLACEHOLDER_MARKERS = (
    "your_", "your-", "yourkey", "xxx", "changeme", "change_me", "placeholder",
    "example", "sample", "dummy", "insert_", "todo", "fixme", "<", "abc123",
    "1234567890", "test_key", "fake", "redacted", "removed", "notreal",
)


def _shannon(s: str) -> float:
    """Randomness score. Real keys score high, English words and paths score low."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(m in low for m in PLACEHOLDER_MARKERS)


def _redact(value: str) -> str:
    # ASCII only — this string ends up in logs and in the prompt, and a stray
    # unicode ellipsis turns into mojibake in some console encodings.
    value = value.strip("\"'")
    return (value[:6] + "...") if len(value) > 6 else "..."


# ── Supabase: the check that matters most for Verilay's audience ──────────────

def _decode_jwt_payload(token: str) -> Optional[dict]:
    """Decode a JWT payload without verifying it. Returns None if not a JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode("utf-8", "replace"))
    except Exception:
        return None


def _supabase_role(token: str) -> Optional[str]:
    """Return 'anon', 'service_role', or None for a Supabase JWT."""
    payload = _decode_jwt_payload(token)
    if not payload:
        return None
    role = payload.get("role")
    if role in ("anon", "service_role"):
        return role
    return None


# ── The scanner ────────────────────────────────────────────────────────────────

def _should_skip(path: str) -> bool:
    low = path.lower()
    if any(part in SKIP_DIRS for part in low.split("/")):
        return True
    if low.endswith(SKIP_SUFFIXES):
        return True
    return False


def scan_file(path: str, content: str) -> List[Finding]:
    if _should_skip(path) or len(content) > MAX_SCAN_BYTES:
        return []

    is_example = any(path.lower().endswith(e) for e in EXAMPLE_FILES)
    findings: List[Finding] = []
    seen = set()

    for lineno, line in enumerate(content.splitlines(), start=1):
        if len(line) > MAX_LINE_LEN:
            continue
        if ENV_REF.search(line):
            continue

        # ── Supabase service_role: the high-value, audience-specific check ──
        for m in re.finditer(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", line):
            role = _supabase_role(m.group(0))
            if role == "anon":
                continue                      # correct by design — never flag
            if role == "service_role":
                key = ("SUPA001", path, lineno)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule_id="SUPA001",
                    name="Supabase service_role key exposed",
                    severity="critical",
                    file=path, line=lineno,
                    preview=_redact(m.group(0)),
                    plain=("Your Supabase master key is in this file. It looks almost identical to the "
                           "safe public key, but it ignores every privacy rule you have set up — anyone "
                           "who finds it can read, change or delete every row in your database, including "
                           "other people's personal details."),
                    action=("Remove it from this file immediately, then go to Supabase → Project Settings → "
                            "API and roll the service_role key. Only ever use the anon (public) key in code "
                            "that runs in the browser."),
                ))

        # ── Everything else ──────────────────────────────────────────────────
        for rule in RULES:
            for m in rule.compiled.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)

                if _looks_placeholder(value):
                    continue
                # PK001 (private key header) fires on documentation/example text too —
                # e.g. a blog post showing "<code>-----BEGIN PRIVATE KEY-----</code>" or
                # prose explaining what a key looks like. A REAL committed key sits at the
                # start of its own line and is immediately followed by base64 key material.
                # Skip the match when it's clearly displayed text, not an actual key.
                if rule.rule_id == "PK001":
                    stripped = line.lstrip()
                    # (a) wrapped in HTML/markdown tags on the same line → it's shown, not stored
                    if ("<code>" in line or "</code>" in line or "<pre>" in line
                            or "`" in line or "</p>" in line or "<p>" in line):
                        continue
                    # (b) header not at the start of the line → embedded in prose, not a real key block
                    if not stripped.startswith("-----BEGIN"):
                        continue
                if rule.needs_entropy and _shannon(value) < 3.5:
                    continue
                # Supabase keys are JWTs. The anon key is correct by design, and the
                # service_role key is already reported as SUPA001 with a far better
                # explanation — so JWT001 must not fire on either, or the user sees
                # the same key twice under two names.
                if rule.rule_id == "JWT001" and _supabase_role(m.group(0)) is not None:
                    continue

                key = (rule.rule_id, path, lineno)
                if key in seen:
                    continue
                seen.add(key)

                sev = "info" if is_example else rule.severity
                findings.append(Finding(
                    rule_id=rule.rule_id, name=rule.name, severity=sev,
                    file=path, line=lineno, preview=_redact(value),
                    plain=(rule.plain if not is_example else
                           f"{rule.name} pattern found in an example file — normally fine, these hold fake values."),
                    action=(rule.action if not is_example else
                            "No action needed unless this is a real key rather than a placeholder."),
                ))

    return findings


def scan_repo(files: Dict[str, str]) -> List[Finding]:
    """Scan every file. Criticals first, then by file."""
    out: List[Finding] = []
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        out.extend(scan_file(path, content))
    order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda f: (order.get(f.severity, 3), f.file, f.line))
    return out


# ── Handing findings to Claude ─────────────────────────────────────────────────

def to_prompt_block(findings: List[Finding], files_scanned: int) -> str:
    """Facts for the prompt. Claude explains and prioritises these — it does not re-detect them."""
    if not findings:
        return (
            f"\n\nCONFIRMED SECRET SCAN: {files_scanned} files were scanned with deterministic pattern "
            "matching across the ENTIRE repository (not just the sample below). No hardcoded secrets "
            "were found. Do NOT invent secret-exposure findings — this check is authoritative and "
            "covers every file.\n\n"
        )

    lines = [
        f"\n\nCONFIRMED SECRET SCAN — {files_scanned} files scanned across the ENTIRE repository "
        "with deterministic pattern matching. These are VERIFIED, not guesses. Treat each as fact, "
        "include every one in your findings at the severity given, and explain it in plain English. "
        "Do NOT downgrade or omit them. Do NOT invent additional secret findings beyond this list.\n"
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.name} — {f.file} line {f.line} (starts '{f.preview}')")
    lines.append("")
    return "\n".join(lines)


def to_report_dict(findings: List[Finding], files_scanned: int) -> dict:
    """Shape for the UI and the saved report."""
    return {
        "files_scanned": files_scanned,
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "warnings": sum(1 for f in findings if f.severity == "warning"),
        "findings": [
            {
                "rule_id": f.rule_id, "name": f.name, "severity": f.severity,
                "file": f.file, "line": f.line, "preview": f.preview,
                "plain": f.plain, "action": f.action,
            }
            for f in findings
        ],
    }


# ── Full-repo fetch: one API call instead of 25 ────────────────────────────────

MAX_TARBALL_BYTES = 60 * 1024 * 1024   # give up rather than stall an analysis


def fetch_all_files_tarball(owner: str, repo: str, token: str = "",
                            max_files: int = 4000, timeout: int = 45) -> Dict[str, str]:
    """
    Download the whole repo as a single tarball and return {path: text}.

    One GitHub API request instead of one per file. Use this for the scanner;
    keep the existing 25-file selection for what Claude reads.

    Streams with a hard size cap. This runs on every GitHub analysis, so a
    pathologically large repo must fail fast rather than hold the request open
    until the platform kills it.
    """
    import io
    import tarfile
    import requests

    hdrs = {"Accept": "application/vnd.github+json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"

    buf = io.BytesIO()
    with requests.get(f"https://api.github.com/repos/{owner}/{repo}/tarball",
                      headers=hdrs, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        total = 0
        for chunk in r.iter_content(chunk_size=1 << 16):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_TARBALL_BYTES:
                raise ValueError("Repository archive too large for a full scan.")
            buf.write(chunk)
    buf.seek(0)

    out: Dict[str, str] = {}
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or len(out) >= max_files:
                continue
            # Strip the "owner-repo-sha/" prefix GitHub adds
            path = member.name.split("/", 1)[1] if "/" in member.name else member.name
            if _should_skip(path) or member.size > MAX_SCAN_BYTES:
                continue
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                out[path] = fh.read().decode("utf-8", "replace")
            except Exception:
                continue
    return out
