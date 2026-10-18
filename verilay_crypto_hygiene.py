"""
verilay_crypto_hygiene.py — deterministic crypto-practice checks for Verilay.

Runs over the same full-repo text the secret scanner already fetches — zero
extra GitHub calls, stdlib only.

This is deliberately NOT a "quantum-ready" check. Post-quantum migration
(NIST's ML-KEM/ML-DSA) happens at the infrastructure layer — Supabase,
Cloudflare, browsers — invisible to and unfixable from inside a Lovable/Replit
user's own repo. Claiming otherwise would be the same false-comfort mistake as
a stale hardcoded CVE list (see verilay_osv_check.py's design notes). What IS
actionable from inside a repo: broken hashes, reversible cipher modes,
hardcoded key material, and undersized RSA keys — bad practice today, and not
coincidentally the same things that will be hardest to migrate once
post-quantum algorithms actually matter.

Design rules, all deliberate:
  * MD5/SHA-1 are only flagged near a password/token/secret keyword within a
    couple of lines either side — hashing a cache key or an ETag with MD5 is
    completely normal and must stay silent. A wrong "info" hit is still noise
    for a non-developer reading the report, so unmatched context means no
    finding at all, not a downgrade.
  * AES-ECB and a literal key/IV passed straight into a cipher call need no
    context check — there is no legitimate reason for either, ever.
  * Only ever return the first 6 characters of a matched literal, same rule
    the secret scanner uses.
  * This module never decides whether a clean scan gets a "no issues" card —
    that is the report layer's call (Moses's decision 2026-09-15: hide the
    section entirely when nothing fires, don't manufacture a clean-state card).

Known limitations (same "narrow but honest" trade the secret scanner makes):
  * Line-by-line matching only — a cipher call whose arguments are split
    across multiple lines will not match. Cheaper to accept than to build a
    multi-line parser for a hygiene check.
  * CRYPTO003 (hardcoded key/IV) currently only covers Node's
    createCipheriv/createDecipheriv shape. Python's pycryptodome
    (AES.new(key, MODE, iv)) is not yet covered — add it the same way if it
    turns out to matter for real repos.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── What never gets scanned — same values as verilay_secret_scan.py ───────────

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

MAX_SCAN_BYTES = 2_000_000
MAX_LINE_LEN = 3_000


def _should_skip(path: str) -> bool:
    low = path.lower()
    if any(part in SKIP_DIRS for part in low.split("/")):
        return True
    if low.endswith(SKIP_SUFFIXES):
        return True
    return False


# ── Findings ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str          # critical | warning — no "info" tier for this module
    file: str
    line: int
    preview: str           # first 6 chars only, same rule as the secret scanner
    plain: str
    action: str


@dataclass
class Rule:
    rule_id: str
    name: str
    regex: str
    severity: str
    plain: str
    action: str
    needs_context: bool = False   # only fire near a password/token/secret keyword
    compiled: Optional[re.Pattern] = field(default=None, repr=False)


# "auth" must be a whole word or start an authentication word: "author" (md5 of an author's email for an avatar image)
# is not a login context.
CONTEXT_WORDS = re.compile(r"(?i)password|passwd|token|secret|\bo?auth(?:entic\w*|oriz\w*)?\b")


# ── The rule set — kept small on purpose ───────────────────────────────────────

RULES: List[Rule] = [
    Rule("CRYPTO001", "Weak hash (MD5/SHA-1) used near a password or token",
         r"(?i)(?:hashlib\.(?:md5|sha1)\s*\(|hashlib\.new\(\s*[\"'](?:md5|sha1)[\"']"              # Python
         r"|createHash\(\s*[\"'](?:md5|sha1)[\"']|CryptoJS\.(?:MD5|SHA1)\s*\(|subtle\.digest\(\s*[\"']sha-?1[\"']"  # Node, browser JS
         r"|(?<![\w.])(?:md5|sha1)\s*\("                                                              # PHP built-ins, helper functions
         r"|MessageDigest\.getInstance\(\s*[\"'](?:md5|sha-?1)[\"']|DigestUtils\.(?:md5|sha1)\w*\("   # Java
         r"|Digest::(?:MD5|SHA1)\b"                                                                   # Ruby
         r"|\b(?:md5|sha1)\.(?:New|Sum)\("                                                            # Go
         r"|\b(?:MD5|SHA1)(?:CryptoServiceProvider|Managed)?\.Create\(|new\s+(?:MD5|SHA1)(?:CryptoServiceProvider|Managed)\b"  # C#
         r"|\b(?:Md5|Sha1)::(?:new|digest)\b)",                                                       # Rust
         "warning",
         "This hashes something with MD5 or SHA-1, both of which are broken for "
         "protecting passwords or tokens — they can be reversed with commodity "
         "hardware in a realistic amount of time.",
         "Use bcrypt, scrypt, or argon2 for passwords. A plain hash — even "
         "SHA-256 — is never enough on its own for anything a login depends on.",
         needs_context=True),

    Rule("CRYPTO002", "AES encryption in ECB mode",
         r"(?i)(?:AES\.MODE_ECB\b|createCipheriv\(\s*[\"']aes-\d+-ecb[\"']|CryptoJS\.mode\.ECB\b)",
         "critical",
         "This encrypts data with AES in ECB mode, which leaks patterns in the "
         "original data — identical blocks of input always produce identical "
         "blocks of output. It's the reason ECB-encrypted images famously still "
         "look like the original picture.",
         "Switch to AES-GCM, which most libraries already default to and also "
         "checks that the data wasn't tampered with. ECB has no legitimate use."),

    Rule("CRYPTO003", "Hardcoded encryption key or IV",
         r"createCipheriv\(\s*[\"'][\w-]+[\"']\s*,\s*[\"']([^\"']{8,})[\"']\s*,\s*[\"']([^\"']{8,})[\"']",
         "critical",
         "The encryption key and/or the IV are typed directly into the code as "
         "fixed text instead of coming from a secret at run time — anyone who "
         "reads this file can decrypt everything ever encrypted with it.",
         "Load the key from an environment variable and generate a fresh random "
         "IV for every single encryption call. Never reuse or hardcode either."),

    Rule("CRYPTO004", "RSA key generation below 2048 bits",
         r"(?i)(?:key_size\s*=\s*(?:512|768|1024)\b|RSA\.generate\(\s*(?:512|768|1024)\s*\)|modulusLength\s*:\s*(?:512|768|1024)\b)",
         "warning",
         "This generates an RSA key smaller than 2048 bits, which is considered "
         "breakable today with enough dedicated computing power.",
         "Generate at least a 2048-bit key (3072+ if this key needs to stay "
         "secure for years)."),
]

for _r in RULES:
    _r.compiled = re.compile(_r.regex)


def _redact(value: str) -> str:
    value = value.strip("\"'")
    return (value[:6] + "...") if len(value) > 6 else "..."


def _has_context(lines: List[str], lineno: int) -> bool:
    """True if a password/token/secret keyword appears within 2 lines either side."""
    lo = max(0, lineno - 3)
    hi = min(len(lines), lineno + 2)
    return any(CONTEXT_WORDS.search(lines[i]) for i in range(lo, hi))


# ── The scanner ────────────────────────────────────────────────────────────────

def scan_file(path: str, content: str) -> List[Finding]:
    if _should_skip(path) or len(content) > MAX_SCAN_BYTES:
        return []

    findings: List[Finding] = []
    seen = set()
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LEN:
            continue
        for rule in RULES:
            m = rule.compiled.search(line)
            if not m:
                continue
            if rule.needs_context and not _has_context(lines, lineno):
                continue   # e.g. MD5 hashing a cache key — normal, stay silent

            key = (rule.rule_id, path, lineno)
            if key in seen:
                continue
            seen.add(key)

            preview = _redact(m.group(1)) if m.groups() else ""
            findings.append(Finding(
                rule_id=rule.rule_id, name=rule.name, severity=rule.severity,
                file=path, line=lineno, preview=preview,
                plain=rule.plain, action=rule.action,
            ))

    return findings


# ── The cross-file hint ────────────────────────────────────────────────────────
# CRYPTO001 only fires when a password/token word sits within two lines of an MD5/SHA-1 call. An app can hash passwords
# through a small helper that wraps the old hash, defined in one file, and call that helper from another file where the
# password is saved; the line-by-line check cannot join the two. Flagging every MD5 call would
# bury cache-key hashing in noise, so this adds only a HINT: "an old hash is used somewhere, and this app also handles
# passwords. Check they are not connected." A hint is not a finding: it is kept apart, never counted as a warning, and
# never changes a grade. It stays silent when the app clearly uses a proper password method (bcrypt, argon2...).

class FindingList(list):
    """The findings, plus `.notes`: 'worth a look' hints that are not findings and are never counted."""

    def __init__(self, items=(), notes=None):
        super().__init__(items)
        self.notes = list(notes or [])


_TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|specs|e2e|cypress|fixtures?|mocks?|__mocks__|stories)(?:/|$)"
                        r"|\.(?:test|spec|stories)\.[a-z]+$|(?:^|/)test_[^/]*$|_test\.[a-z]+$")
_CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".swift")
_PASSWORD_HASHING = re.compile(r"(?i)\bpass(?:word|wd)\w*\b[^\n]{0,80}?\b(?:hash|crypt|digest|compare|verify)\w*"
                               r"|\b(?:hash|crypt|digest|compare|verify)\w*\b[^\n]{0,80}?\bpass(?:word|wd)")
_STRONG_PASSWORD_METHOD = re.compile(
    r"(?i)\b(?:bcrypt\w*|scrypt\w*|argon2\w*|pbkdf2\w*|hashpw|passlib|generate_password_hash|check_password_hash"
    r"|password_hash|password_verify|make_password|check_password|has_secure_password|\w*PasswordEncoder|PasswordHasher"
    r"|Rfc2898DeriveBytes)\b|Hash::make")
_PASSWORD_WORD = re.compile(r"(?i)\bpass(?:word|wd)")


def cross_file_notes(files: Dict[str, str], findings=()) -> List[dict]:
    """At most one hint for the whole repo (see the block comment above). Never raises."""
    try:
        if any(f.rule_id == "CRYPTO001" for f in findings):
            return []                                   # the real check already fired; no hint needed
        weak = None                                     # (path, line) of the first MD5/SHA-1 call in app code
        pw_hash = None                                  # (path, line) of the first line that hashes/compares a password
        strong = False
        for path, content in files.items():
            if (not isinstance(content, str) or _should_skip(path) or _TEST_PATH.search(path)
                    or not path.lower().endswith(_CODE_EXT) or len(content) > MAX_SCAN_BYTES):
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                if len(line) > MAX_LINE_LEN:
                    continue
                if weak is None and RULES[0].compiled.search(line):
                    weak = (path, lineno)
                if _PASSWORD_WORD.search(line):
                    if _STRONG_PASSWORD_METHOD.search(line):
                        strong = True
                    if pw_hash is None and _PASSWORD_HASHING.search(line):
                        pw_hash = (path, lineno)
        if not weak or not pw_hash or strong:
            return []
        return [{
            "rule_id": "CRYPTO001-HINT", "severity": "note",
            "name": "An old hash (MD5 or SHA-1) is used, and this app also handles passwords",
            "file": weak[0], "line": weak[1], "preview": "",
            "plain": (f"{weak[0]} line {weak[1]} hashes with MD5 or SHA-1, which are broken for protecting passwords. "
                      f"The app also appears to hash or check passwords ({pw_hash[0]} line {pw_hash[1]}). Verilay "
                      "can't tell whether the two are connected, so this is a pointer to check, not a confirmed problem."),
            "action": ("Check what that hash is used for. If it protects passwords or login tokens, replace it with "
                       "bcrypt, scrypt or argon2. If it is only a cache label, you can ignore this."),
        }]
    except Exception:
        return []


def scan_repo(files: Dict[str, str]) -> List[Finding]:
    """Scan every file. Criticals first, then by file. The returned list also carries `.notes` (see cross_file_notes)."""
    out: List[Finding] = []
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        out.extend(scan_file(path, content))
    order = {"critical": 0, "warning": 1}
    out.sort(key=lambda f: (order.get(f.severity, 2), f.file, f.line))
    return FindingList(out, cross_file_notes(files, out))


# ── Handing findings to Claude ─────────────────────────────────────────────────

def to_prompt_block(findings: List[Finding], files_scanned: int) -> str:
    """Facts for the prompt. Claude explains and prioritises these — it does not re-detect them."""
    if not findings:
        return (
            f"\n\nCONFIRMED CRYPTO HYGIENE CHECK: {files_scanned} files were scanned "
            "deterministically for weak hashes near passwords/tokens, AES-ECB mode, "
            "hardcoded encryption keys/IVs, and undersized RSA keys. None were found. "
            "Do NOT invent crypto-practice findings — this check is authoritative for "
            "these specific patterns.\n\n"
        )

    lines = [
        f"\n\nCONFIRMED CRYPTO HYGIENE CHECK — {files_scanned} files scanned "
        "deterministically. These are VERIFIED, not guesses. Include each at the "
        "severity given and explain it in plain English. Do NOT downgrade, omit, "
        "or invent additional crypto-practice findings beyond this list.\n"
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.name} — {f.file} line {f.line}")
    lines.append("")
    return "\n".join(lines)


def to_report_dict(findings: List[Finding], files_scanned: int) -> dict:
    """Shape for the UI and the saved report — same contract as the secret scanner."""
    return {
        "files_scanned": files_scanned,
        "notes": [dict(n) for n in (getattr(findings, "notes", None) or [])],   # hints only: never counted below
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
