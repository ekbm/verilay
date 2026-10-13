"""
verilay_authz_check.py — deterministic "who can do what" checks for Verilay (Stage 3, step 2).

Same idea as verilay_secret_scan.py: fixed rules, no AI, the same answer every run, and it
runs over the full-repo text Verilay has already fetched (no extra network calls, no extra
AI calls, milliseconds of work).

Audience: people who built an app with an AI tool and cannot read code. So every finding
carries (a) a plain-English title and explanation with no jargon, (b) the exact file and
line, and (c) a ready-to-paste prompt for their AI builder.

ONLY for Supabase apps. These rules rest on how Supabase works: its database is reachable straight from the
internet with a public key, so a table without row protection really is open. In an app with its own server in
front of its database (Express with Drizzle or Prisma, Django, Rails, Laravel ...) the same SQL is normal, and
flagging it would be a false alarm. So a repo is only checked when it shows clear Supabase signals (see
_looks_like_supabase). Added 2026-10-13 after a Drizzle app was wrongly marked as having 30 serious problems.

What it reads, for apps that use Supabase (Lovable's default backend):
  * supabase/migrations/*.sql   — database functions, tables, row protection, access rules,
                                   and who was granted or refused permission to use them
  * supabase/config.toml        — which backend functions skip the platform's login check
  * supabase/functions/*/index.ts — what those backend functions actually do

Rules in this first version (two levels, on purpose):
  DEFINITE (counts toward the grade — narrow, clear-cut cases only)
    R1  A database function that runs with full access, writes data (or looks up a person's
        data), never checks who is calling, and is open to people who are not signed in.
    R2  A table with no row protection that anonymous visitors can use, or a rule that lets
        anonymous visitors change every row.
    R3  A backend function that skips the login check, uses full admin access, and updates or
        deletes a row chosen by something in the request, with no check of any kind.
  REVIEW (shown as "please check", NEVER affects the grade — plausible but uncertain)
    the same patterns where only signed-in users are involved, where the permission state is
    unclear, or where the function is open but only reads, sends email or calls an AI model.

Known limits, stated in every result: it reads the files in the repository, not the live
database, so settings changed in the Supabase dashboard are invisible to it; it understands
plain SQL migrations, not SQL generated at run time; and a "no findings" result is not a
guarantee. Public read-only helpers and the standard "has_role" helper that access rules
call are deliberately NOT flagged, to keep false alarms rare.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

SCOPE_NOTE = ("Based on the database and function files in your repository. Settings changed directly "
              "in the Supabase dashboard cannot be seen here and may differ.")
MAX_FINDINGS = 40
MAX_FILE_BYTES = 2_000_000


@dataclass
class Finding:
    rule_id: str        # R1 | R2 | R3
    level: str          # definite | review
    severity: str       # critical (definite only) | review
    title: str          # plain English headline
    plain: str          # what it means, in plain English
    file: str
    line: int
    subject: str        # the function / table / backend function name
    fix_prompt: str     # paste-ready prompt for the person's AI builder


class FindingList(list):
    """A plain list of findings that also remembers what was looked at."""
    applicable = False
    sql_files = 0
    database_functions = 0
    tables = 0
    backend_functions = 0


# ── A small SQL reader: comments removed, statements split, strings and $$ bodies respected ──

_DOLLAR = re.compile(r"\$[A-Za-z_]*\$")


def _split_statements(sql: str) -> List[Tuple[str, int]]:
    """[(statement_text, first_line)] with comments removed. Quotes and $tag$ bodies are kept whole."""
    out: List[Tuple[str, int]] = []
    buf: List[str] = []
    i, n, line = 0, len(sql), 1
    start: Optional[int] = None

    def add(seg: str):
        nonlocal start, line
        if start is None and seg.strip():
            start = line + (len(seg) - len(seg.lstrip("\n"))) if seg.startswith("\n") else line
        buf.append(seg)
        line += seg.count("\n")

    def flush():
        nonlocal buf, start
        text = "".join(buf).strip()
        if text:
            out.append((text, start or 1))
        buf, start = [], None

    while i < n:
        c = sql[i]
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            seg = sql[i:j]
            line += seg.count("\n")
            buf.append(" ")
            i = j
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            add(sql[i:j + 1])
            i = j + 1
            continue
        if c == "$":
            m = _DOLLAR.match(sql, i)
            if m:
                tag = m.group(0)
                j = sql.find(tag, m.end())
                j = n if j == -1 else j + len(tag)
                add(sql[i:j])
                i = j
                continue
        if c == ";":
            flush()
            i += 1
            continue
        if c == "\n":
            if start is not None:
                buf.append(c)
            line += 1
            i += 1
            continue
        if start is None and not c.isspace():
            start = line
        buf.append(c)
        i += 1
    flush()
    return out


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _clean_name(raw: str) -> Optional[str]:
    """public.foo / "foo" / foo  ->  foo.  Names in other schemas return None (not exposed to the API)."""
    raw = raw.strip()
    parts = [p.strip().strip('"') for p in re.split(r"\.(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", raw)]
    if len(parts) == 2:
        if parts[0].lower() != "public":
            return None
        return parts[1].lower()
    return parts[0].lower() if parts and parts[0] else None


def _balanced(text: str, open_idx: int) -> int:
    """Index of the ')' that closes the '(' at open_idx, or -1."""
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


# ── What the SQL says ──────────────────────────────────────────────────────────

_FN_RE = re.compile(r"^create\s+(?:or\s+replace\s+)?function\s+((?:\"[^\"]+\"|\w+)(?:\s*\.\s*(?:\"[^\"]+\"|\w+))?)\s*\(", re.I)
_CALLER_CHECK = re.compile(
    r"auth\.uid\s*\(|auth\.jwt\s*\(|auth\.role\s*\(|auth\.email\s*\(|current_setting\s*\(\s*'request\.jwt"
    r"|\bhas_role\s*\(|\bis_admin\b|\bis_service_role\b"
    r"|\b(?:is|has|check|require|assert|ensure|can|authorize|verify)_\w+\s*\(", re.I)
_WRITES = re.compile(r"\b(insert\s+into|update\s+[\w\.\"]+\s+set|delete\s+from|truncate\b|drop\s+(?:table|function|policy)|alter\s+table)\b", re.I)
_READS = re.compile(r"\bselect\b", re.I)
_IDENTITY_ARG = re.compile(r"\b\w*(?:user|owner|account|profile|org|team|tenant|email)\w*\b|\b\w*_id\b|\bid\b", re.I)
_PERSONAL_COL = re.compile(r"^(user_id|owner_id|email|phone|full_name|first_name|last_name|address|ip_address|customer_id|stripe_customer_id)$")
_CONSTRAINT_START = ("constraint", "primary", "foreign", "unique", "check", "exclude", "like")


@dataclass
class _Fn:
    name: str
    file: str
    line: int
    definer: bool
    trigger: bool
    caller_check: bool
    writes: bool
    reads: bool
    identity_arg: bool
    anon: str = "open"      # open | public_only | locked
    authed: str = "open"    # open | locked


@dataclass
class _Table:
    name: str
    file: str
    line: int
    cols: List[str]
    rls: bool = False
    anon: str = "open"      # open | locked
    authed: str = "open"


@dataclass
class _Policy:
    table: str
    name: str
    file: str
    line: int
    cmd: str
    roles: List[str]
    using: str
    check: str


def _parse_function(stmt: str, path: str, line: int) -> Optional[_Fn]:
    m = _FN_RE.match(stmt)
    if not m:
        return None
    name = _clean_name(m.group(1))
    if not name:
        return None
    open_idx = m.end() - 1
    close_idx = _balanced(stmt, open_idx)
    if close_idx == -1:
        return None
    args = stmt[open_idx + 1:close_idx]
    rest = stmt[close_idx + 1:]
    dm = _DOLLAR.search(rest)
    if dm:
        end = rest.find(dm.group(0), dm.end())
        body = rest[dm.end(): end if end != -1 else len(rest)]
        outside = rest[:dm.start()] + (rest[end + len(dm.group(0)):] if end != -1 else "")
    else:
        body, outside = rest, rest
    low_out = _norm(outside)
    return _Fn(
        name=name, file=path, line=line,
        definer="security definer" in low_out,
        trigger=bool(re.search(r"\breturns\s+(?:event_)?trigger\b", low_out)),
        caller_check=bool(_CALLER_CHECK.search(body)),
        writes=bool(_WRITES.search(body)),
        reads=bool(_READS.search(body)),
        identity_arg=bool(args.strip() and _IDENTITY_ARG.search(args)),
    )


def _parse_table(stmt: str, path: str, line: int) -> Optional[_Table]:
    m = re.match(r"^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:\"[^\"]+\"|\w+)(?:\s*\.\s*(?:\"[^\"]+\"|\w+))?)\s*\(", stmt, re.I)
    if not m:
        return None
    name = _clean_name(m.group(1))
    if not name:
        return None
    close_idx = _balanced(stmt, m.end() - 1)
    inner = stmt[m.end(): close_idx if close_idx != -1 else len(stmt)]
    cols, depth, cur = [], 0, ""
    for ch in inner + ",":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            first = cur.strip().split(None, 1)[0].strip('"').lower() if cur.strip() else ""
            if first and first not in _CONSTRAINT_START:
                cols.append(first)
            cur = ""
        else:
            cur += ch
    return _Table(name=name, file=path, line=line, cols=cols)


def _roles(text: str) -> List[str]:
    return [r.strip().strip('"').lower() for r in text.split(",") if r.strip()]


def _clause(stmt: str, keyword: str) -> str:
    """Contents of the (...) after `using` / `with check` in a policy statement."""
    m = re.search(r"\b" + keyword + r"\s*\(", stmt, re.I)
    if not m:
        return ""
    close_idx = _balanced(stmt, m.end() - 1)
    return stmt[m.end(): close_idx if close_idx != -1 else len(stmt)].strip()


def _parse_policy(stmt: str, path: str, line: int) -> Optional[_Policy]:
    m = re.match(r"^create\s+policy\s+(\"[^\"]+\"|\w+)\s+on\s+((?:\"[^\"]+\"|\w+)(?:\s*\.\s*(?:\"[^\"]+\"|\w+))?)(.*)$", stmt, re.I | re.S)
    if not m:
        return None
    table = _clean_name(m.group(2))
    if not table:
        return None
    tail = m.group(3)
    low = _norm(tail)
    cmd = "all"
    cm = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", low)
    if cm:
        cmd = cm.group(1)
    roles: List[str] = []
    rm = re.search(r"\bto\s+(.+?)(?=\s+using\b|\s+with\s+check\b|$)", low)
    if rm:
        roles = _roles(rm.group(1))
    return _Policy(table=table, name=m.group(1).strip('"').lower(), file=path, line=line, cmd=cmd, roles=roles,
                   using=_norm(_clause(tail, "using")), check=_norm(_clause(tail, r"with\s+check")))


def _is_true(expr: str) -> bool:
    return _norm(expr).strip("() ") in ("true", "1=1", "1 = 1")


def _apply_grants(stmt: str, fns: Dict[str, _Fn], tables: Dict[str, _Table]) -> None:
    low = _norm(stmt)
    m = re.match(r"^(revoke|grant)\s+(.*?)\s+on\s+(.*?)\s+(from|to)\s+(.+)$", low)
    if not m:
        return
    verb, privs, target, _, who = m.groups()
    roles = _roles(re.sub(r"\s+(cascade|restrict|with grant option|granted by .*)$", "", who))
    is_revoke = verb == "revoke"
    all_privs = privs.startswith("all") or "execute" in privs
    state = "locked" if is_revoke else "open"

    def set_fn(fn: _Fn):
        if not all_privs:
            return
        if "anon" in roles:
            fn.anon = state
        elif "public" in roles and is_revoke and fn.anon != "locked":
            fn.anon = "public_only"
        elif "public" in roles and not is_revoke:
            fn.anon = "open"
        if "authenticated" in roles:
            fn.authed = state
        elif "public" in roles:
            fn.authed = state

    def set_tbl(t: _Table):
        if is_revoke and not privs.startswith("all"):
            return          # a partial revoke leaves some access in place: treat as still open
        if "anon" in roles or "public" in roles:
            t.anon = state
        if "authenticated" in roles or "public" in roles:
            t.authed = state

    fm = re.match(r"^(?:function|routine)\s+(.+)$", target)
    if fm:
        if fm.group(1).startswith("all"):
            for fn in fns.values():
                set_fn(fn)
            return
        for item in re.split(r",\s*(?![^()]*\))", fm.group(1)):
            nm = _clean_name(re.sub(r"\s*\(.*$", "", item).strip())
            if nm and nm in fns:
                set_fn(fns[nm])
        return
    if re.match(r"^all (?:functions|routines) in schema public$", target):
        for fn in fns.values():
            set_fn(fn)
        return
    if re.match(r"^all tables in schema public$", target):
        for t in tables.values():
            set_tbl(t)
        return
    tm = re.match(r"^(?:table\s+)?(.+)$", target)
    if tm and not target.startswith(("schema", "sequence", "database", "type", "all ")):
        for item in tm.group(1).split(","):
            nm = _clean_name(item.strip())
            if nm and nm in tables:
                set_tbl(tables[nm])


# ── Backend functions (supabase/functions/*/index.ts) ───────────────────────────

_GUARD = re.compile(
    r"auth\.getUser|getClaims\s*\(|\.getUser\s*\("
    r"|headers\.get\(\s*['\"](?:authorization|x-[\w-]*(?:secret|token|key|signature)[\w-]*|stripe-signature|svix-[\w-]+)['\"]"
    r"|constructEvent(?:Async)?\s*\(|new\s+Webhook\s*\(|timingSafeEqual"
    r"|CRON_SECRET|WEBHOOK_SECRET|INTERNAL_SECRET"
    r"|\b(?:require|verify|check|assert|ensure|get)\w*(?:Auth|User|Admin|Jwt|Token|Secret)\w*\s*\("
    r"|from\s+['\"][^'\"]*_shared/(?:auth|guard|security)[^'\"]*['\"]", re.I)
_SERVICE_ROLE = re.compile(r"SERVICE_ROLE|service_role", re.I)
_UPDATE_BY_VAR = re.compile(r"\.(?:update|delete)\s*\(", re.I)
_EQ_VARIABLE = re.compile(r"\.eq\s*\(\s*['\"]\w+['\"]\s*,\s*(?!['\"`0-9])[\w\.\[\]]+", re.I)
_READS_REQUEST = re.compile(r"req(?:uest)?\.json\s*\(|new\s+URL\s*\(\s*req", re.I)
_ANY_WRITE = re.compile(r"\.(?:insert|update|upsert|delete)\s*\(", re.I)
_AI_CALL = re.compile(r"generativelanguage|anthropic|openai|ai\.gateway|ai\.lovable|api\.groq|mistral", re.I)
_SENDS_EMAIL = re.compile(r"resend|sendgrid|postmark|smtp|ses\.amazonaws|zeptomail|mailgun", re.I)


def _jwt_settings(toml: str) -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for m in re.finditer(r"\[functions\.\"?([\w-]+)\"?\]\s*(?:#[^\n]*\n|\s)*?verify_jwt\s*=\s*(true|false)", toml, re.I):
        out[m.group(1)] = (m.group(2).lower() == "true")
    return out


# ── Wording (plain English; the prompts are for the AI builder, so they may be technical) ──

def _fix_prompt(kind: str, subject: str, file: str, extra: str = "") -> str:
    tail = (" Show me exactly what you change, keep everything else working, and explain it in plain English.")
    if kind == "R1":
        return (f"In my Supabase project, the database function `{subject}` (see {file}) runs with full access "
                "to my data but does not check who is calling it. Please make it check the caller with "
                "auth.uid() (and my roles table if I have one) so people can only act on their own data. "
                "If it should never be called from the app, revoke EXECUTE on it from anon and authenticated "
                "instead." + tail)
    if kind == "R2_norls":
        return (f"In my Supabase project, the table public.{subject} (see {file}) has no row level security. "
                "Please enable row level security on it and add policies so each signed-in user can only read "
                "and change their own rows (use auth.uid()). If some rows are meant to be public, add a "
                "read-only policy for those. Do not remove features that already work." + tail)
    if kind == "R2_policy":
        return (f"In my Supabase project, a rule on the table public.{subject} (see {file}) lets anyone, even "
                "visitors who are not signed in, add, change or delete rows. Please replace it with a policy "
                "that only lets signed-in users change their own rows (use auth.uid())." + tail)
    if kind == "R3":
        return (f"My Supabase edge function `{subject}` (see {file}) can be called by anyone because "
                "verify_jwt is false, and it updates or deletes a row chosen by the request using the "
                "service role key. Please require a signed-in user (check the Authorization header with "
                "supabase.auth.getUser) and make sure that user owns the row before changing it." + tail)
    return (f"Please review `{subject}` (see {file}). {extra}" + tail)


def _finding(rule, level, title, plain, file, line, subject, prompt) -> Finding:
    return Finding(rule_id=rule, level=level, severity="critical" if level == "definite" else "review",
                   title=title, plain=plain, file=file, line=line, subject=subject, fix_prompt=prompt)


# ── The scan ───────────────────────────────────────────────────────────────────

def _is_sql_path(low: str) -> bool:
    return low.endswith(".sql") and ("migrations/" in low or low.startswith("supabase/") or "/supabase/" in low)


_SUPABASE_SQL = re.compile(r"auth\.uid\s*\(|auth\.jwt\s*\(|\bto\s+(?:anon|authenticated)\b|\bservice_role\b|supabase", re.I)


def _looks_like_supabase(files: Dict[str, str]) -> bool:
    """True only when the repo clearly uses Supabase: a supabase/ folder, the Supabase library in
    package.json / requirements, or SQL that uses Supabase-only things (auth.uid(), the anon and
    authenticated roles). A plain migrations/ folder of CREATE TABLE statements is NOT enough."""
    for path, text in files.items():
        low = path.lower()
        if low.startswith("supabase/") or "/supabase/" in low:
            return True
        if not isinstance(text, str):
            continue
        if low.endswith("package.json") and "@supabase/" in text:
            return True
        if low.endswith(("requirements.txt", "pyproject.toml", "pipfile")) and re.search(r"\bsupabase\b", text, re.I):
            return True
    for path, text in files.items():
        if isinstance(text, str) and _is_sql_path(path.lower()) and _SUPABASE_SQL.search(text[:MAX_FILE_BYTES]):
            return True
    return False


def scan_repo(files: Dict[str, str]) -> FindingList:
    """Run every rule. Never raises. Definite findings first, then review ones."""
    result = FindingList()
    try:
        _scan(files, result)
    except Exception as e:   # a parsing surprise must never take down an analysis
        print(f"Access check skipped: {e}", flush=True)
    return result


def _scan(files: Dict[str, str], result: FindingList) -> None:
    if not _looks_like_supabase(files):
        return                      # not a Supabase app: these rules do not apply, say nothing
    fns: Dict[str, _Fn] = {}
    tables: Dict[str, _Table] = {}
    policies: Dict[Tuple[str, str], _Policy] = {}
    policy_text = []
    dynamic_rls = False
    sql_paths = sorted(p for p in files if isinstance(files.get(p), str) and _is_sql_path(p.lower())
                       and len(files[p]) <= MAX_FILE_BYTES)
    for path in sql_paths:
        result.sql_files += 1
        for stmt, line in _split_statements(files[path]):
            low = _norm(stmt)
            if low.startswith("create") and " function " in low[:40]:
                fn = _parse_function(stmt, path, line)
                if fn:
                    old = fns.get(fn.name)
                    if old:                      # CREATE OR REPLACE keeps the permissions already granted
                        fn.anon, fn.authed = old.anon, old.authed
                    fns[fn.name] = fn
            elif re.match(r"^create (?:unlogged )?table ", low):
                t = _parse_table(stmt, path, line)
                if t:
                    tables[t.name] = t
            elif low.startswith("alter table"):
                am = re.match(r"^alter table (?:if exists )?(?:only )?(.+?) (enable|disable) row level security", low)
                if am:
                    nm = _clean_name(am.group(1))
                    if nm in tables:
                        tables[nm].rls = (am.group(2) == "enable")
            elif low.startswith("create policy"):
                p = _parse_policy(stmt, path, line)
                if p:
                    policies[(p.table, p.name)] = p
                policy_text.append(low)
            elif low.startswith("drop policy"):
                dm = re.match(r"^drop policy (?:if exists )?(\"[^\"]+\"|\w+) on (.+)$", stmt.strip(), re.I)
                if dm:
                    policies.pop((_clean_name(dm.group(2)) or "", dm.group(1).strip('"').lower()), None)
            elif low.startswith("drop table"):
                for item in re.sub(r"^drop table (?:if exists )?", "", low).split(","):
                    tables.pop(_clean_name(item.strip().split()[0]) or "", None)
            elif low.startswith("drop function"):
                dn = re.match(r"^drop function (?:if exists )?([^\s(]+)", low)
                if dn:
                    fns.pop(_clean_name(dn.group(1)) or "", None)
            elif low.startswith(("revoke", "grant")):
                _apply_grants(stmt, fns, tables)
            elif low.startswith("do ") and "row level security" in low:
                dynamic_rls = True

    # which functions are really helpers that access rules call (has_role-style): not a problem to flag
    helper_names = {n for n in fns if any(re.search(r"\b" + re.escape(n) + r"\s*\(", t) for t in policy_text)}

    result.database_functions = sum(1 for f in fns.values() if f.definer and not f.trigger)
    result.tables = len(tables)
    findings: List[Finding] = []

    # R1 ─ database functions
    for fn in fns.values():
        if not fn.definer or fn.trigger or fn.caller_check or fn.name in helper_names:
            continue
        risky = fn.writes or (fn.identity_arg and fn.reads)
        if not risky:
            continue                 # a public read-only helper: normal, stay silent
        if fn.anon == "open":
            findings.append(_finding(
                "R1", "definite", f"Anyone on the internet can trigger the database action \"{fn.name}\"",
                f"The database action \"{fn.name}\" runs with full access to your data and never checks who is asking. "
                "Your app's public key is visible to every visitor, and that key is enough to call it.",
                fn.file, fn.line, fn.name, _fix_prompt("R1", fn.name, fn.file)))
        elif fn.anon == "public_only" or fn.authed == "open":
            why = ("It was only removed from the general public group, and the platform may still let visitors call it."
                   if fn.anon == "public_only" else "Any signed-in user can call it.")
            findings.append(_finding(
                "R1", "review", f"Please check who can run the database action \"{fn.name}\"",
                f"The database action \"{fn.name}\" runs with full access to your data and does not check which user is asking. {why}",
                fn.file, fn.line, fn.name, _fix_prompt("R1", fn.name, fn.file)))

    # R2 ─ tables and access rules
    for t in tables.values():
        if not t.rls:
            if t.anon == "open":
                lvl = "review" if dynamic_rls else "definite"
                findings.append(_finding(
                    "R2", lvl, f"The table \"{t.name}\" has no protection on its rows",
                    f"Anyone who has your app's public key can read, change or delete every row in \"{t.name}\", "
                    "including other people's data."
                    + (" (This could not be fully confirmed because some of your setup is written as code that runs later.)" if dynamic_rls else ""),
                    t.file, t.line, t.name, _fix_prompt("R2_norls", t.name, t.file)))
            elif t.authed == "open":
                findings.append(_finding(
                    "R2", "review", f"Please check the table \"{t.name}\": any signed-in user can use every row",
                    f"The table \"{t.name}\" has no row protection, so any signed-in user may be able to read or change everyone's rows.",
                    t.file, t.line, t.name, _fix_prompt("R2_norls", t.name, t.file)))
    for p in policies.values():
        t = tables.get(p.table)
        if not t or not t.rls:
            continue
        everyone = (not p.roles) or any(r in ("public", "anon") for r in p.roles)
        signed_in = any(r == "authenticated" for r in p.roles)
        writes = p.cmd in ("all", "insert", "update", "delete")
        true_rule = _is_true(p.using) or _is_true(p.check)
        if writes and true_rule and everyone:
            findings.append(_finding(
                "R2", "definite", f"Anyone can change the rows in \"{p.table}\"",
                f"A rule on \"{p.table}\" lets anyone, even visitors who are not signed in, add, change or delete rows.",
                p.file, p.line, p.table, _fix_prompt("R2_policy", p.table, p.file)))
        elif writes and true_rule and signed_in:
            findings.append(_finding(
                "R2", "review", f"Please check: any signed-in user can change every row in \"{p.table}\"",
                f"A rule on \"{p.table}\" lets any signed-in user change all rows, not just their own. That is fine only if everyone is meant to share this data.",
                p.file, p.line, p.table, _fix_prompt("R2_policy", p.table, p.file)))
        elif p.cmd == "select" and _is_true(p.using) and everyone and any(_PERSONAL_COL.match(c) for c in t.cols):
            findings.append(_finding(
                "R2", "review", f"Please check: everyone can read all rows of \"{p.table}\"",
                f"A rule on \"{p.table}\" lets anyone read every row, and the table has columns that look personal (such as an email or user id).",
                p.file, p.line, p.table, _fix_prompt("review", p.table, p.file, "Everyone can read all rows and the table has columns that look personal. Make sure that is intended.")))

    # R3 ─ backend functions
    cfg_path = next((p for p in files if p.lower().endswith("supabase/config.toml")), None)
    jwt = _jwt_settings(files[cfg_path]) if cfg_path and isinstance(files.get(cfg_path), str) else {}
    for path, text in files.items():
        low = path.lower()
        m = re.match(r"^(?:.*/)?supabase/functions/([^/]+)/index\.(?:ts|js|tsx|mjs)$", low)
        if not m or not isinstance(text, str) or m.group(1).startswith("_"):
            continue
        name = path.split("supabase/functions/", 1)[1].split("/", 1)[0] if "supabase/functions/" in path else m.group(1)
        result.backend_functions += 1
        if jwt.get(name) is not False:
            continue                  # the platform checks the login for this function
        if _GUARD.search(text):
            continue                  # some check is visible in the code: do not second-guess it
        uses_admin = bool(_SERVICE_ROLE.search(text))
        by_request = bool(uses_admin and _UPDATE_BY_VAR.search(text) and _EQ_VARIABLE.search(text) and _READS_REQUEST.search(text))
        line = next((i + 1 for i, l in enumerate(text.splitlines()) if "serve(" in l or "Deno.serve" in l), 1)
        if by_request:
            findings.append(_finding(
                "R3", "definite", f"The backend function \"{name}\" changes data for anyone who calls it",
                f"\"{name}\" can be called by anyone on the internet, uses full admin access to your data, and changes or deletes a record chosen by the request, without checking who is asking.",
                path, line, name, _fix_prompt("R3", name, path)))
        elif uses_admin or _AI_CALL.search(text) or _SENDS_EMAIL.search(text) or _ANY_WRITE.search(text):
            doing = ("uses full admin access to your data" if uses_admin else
                     "calls an AI model, which costs you money on every call" if _AI_CALL.search(text) else
                     "sends email" if _SENDS_EMAIL.search(text) else "writes to your data")
            findings.append(_finding(
                "R3", "review", f"Please check: the backend function \"{name}\" is open to everyone",
                f"\"{name}\" can be called by anyone without signing in, and it {doing}. That is fine only if it is meant to be public.",
                path, line, name, _fix_prompt("review", name, path, f"This function can be called by anyone and it {doing}. Make sure that is intended, and add a login or secret check if not.")))

    findings.sort(key=lambda f: (0 if f.level == "definite" else 1, f.rule_id, f.file, f.line))
    result.extend(findings[:MAX_FINDINGS])
    result.applicable = bool(sql_paths) or result.backend_functions > 0 or bool(cfg_path)


# ── Handing results on (same shapes as the other scanners) ─────────────────────

# However many clear-cut findings there are, they can lower the grade by at most this many "critical" counts
# (a D). A rule can still be wrong in a way the tests did not foresee; one family of rules must never be able
# to produce an F on its own. The full count is still shown on the report.
GRADE_CAP = 5


def severity_counts(findings) -> Tuple[int, int]:
    """(critical, warning) that may count toward the grade: DEFINITE findings only, always critical, capped."""
    return min(sum(1 for f in findings if f.level == "definite"), GRADE_CAP), 0


def _counts(findings) -> Tuple[int, int]:
    return (sum(1 for f in findings if f.level == "definite"), sum(1 for f in findings if f.level == "review"))


def _scope(findings) -> dict:
    return {"database_functions": getattr(findings, "database_functions", 0), "tables": getattr(findings, "tables", 0),
            "backend_functions": getattr(findings, "backend_functions", 0), "sql_files": getattr(findings, "sql_files", 0)}


def to_prompt_block(findings, free: bool = False) -> str:
    """Facts for the AI. It explains and prioritises these; it does not re-detect them. Empty when the app
    has no Supabase files (nothing to say)."""
    if not getattr(findings, "applicable", False):
        return ""
    definite, review = _counts(findings)
    if not findings:
        return ("\n\nCONFIRMED ACCESS-RULE CHECK: the database and backend-function files were read by fixed rules and "
                "no obvious who-can-do-what problems were found. This only covers the files in the repository, not live "
                "dashboard settings. Do NOT invent access-control findings from these files.\n\n")
    if free:
        ex = next((f for f in findings if f.level == "definite"), findings[0])
        return (f"\n\nCONFIRMED ACCESS-RULE CHECK (FREE TIER): fixed rules found {definite} serious and {review} to review "
                f"who-can-do-what problems. Mention only these counts and this one example: \"{ex.title}\" ({ex.file}). "
                "Say a deep scan lists every one with a ready-to-paste fix. Do not name any other tables or functions.\n\n")
    lines = ["\n\nCONFIRMED ACCESS-RULE CHECK — found by fixed rules, VERIFIED, not guesses. Include each [SERIOUS] one as "
             "critical in plain English. Items marked [REVIEW] are only 'please check' and must NOT be called critical. "
             "Do not invent more access-control findings from these files.\n"]
    for f in findings:
        lines.append(f"- [{'SERIOUS' if f.level == 'definite' else 'REVIEW'}] {f.title} — {f.file} line {f.line}")
    lines.append("")
    return "\n".join(lines)


def to_teaser_dict(findings) -> dict:
    """The FREE report: counts and ONE example, no list of files or names beyond that."""
    definite, review = _counts(findings)
    ex = next((f for f in findings if f.level == "definite"), next(iter(findings), None))
    return {
        "applicable": bool(getattr(findings, "applicable", False)),
        "critical": definite, "review": review, "scope": _scope(findings), "scope_note": SCOPE_NOTE,
        "example": ({"title": ex.title, "plain": ex.plain, "file": ex.file, "line": ex.line, "level": ex.level} if ex else None),
    }


def to_report_dict(findings) -> dict:
    """The DEEP report: every finding, with its ready-to-paste fix."""
    definite, review = _counts(findings)
    return {
        "applicable": bool(getattr(findings, "applicable", False)),
        "critical": definite, "review": review, "scope": _scope(findings), "scope_note": SCOPE_NOTE,
        "findings": [
            {"rule_id": f.rule_id, "level": f.level, "severity": f.severity, "title": f.title, "plain": f.plain,
             "file": f.file, "line": f.line, "subject": f.subject, "fix_prompt": f.fix_prompt}
            for f in findings
        ],
    }
