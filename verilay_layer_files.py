"""
verilay_layer_files.py: which files each layer gets to read (2026-10-14).

Each layer of a report (Auth, Config, Database, API, Frontend) is written by asking the AI about a handful of
files. Those files used to be chosen by FILE NAME alone ("auth", "config", "db", "route", "api", ...), at most six.
That works for tidy apps with folders called auth/ and routes/, but not for the flat apps AI tools often make
(everything in a few Python files with names like accounts.py or app.py): Verilay's own deep scan read all 34 of
its files yet reported Auth, Config, Database and Frontend as "Not checked", because none of the chosen files
looked like those layers, even though the login code sat in verilay_accounts.py.

Now a file is chosen for a layer by what is INSIDE it as well as its name: a file full of password and session
handling is login code whatever it is called. Name hints still count (everything the old rule picked still scores
well), page files (.tsx, .html, .css ...) count for Frontend, and a file that is mostly about one thing beats a huge
file that merely mentions it. No AI is involved and nothing is added to the AI calls: same number of calls, same
size limit; only the choice of files changes.

Set VERILAY_LAYER_FILES=old to go back to the name-only rule without a deploy.
"""
import os
import re

# More files than the old limit of 6 are shown only when they are small: the caller still caps the total text.
FILES_PER_LAYER = 3
MAX_FILES = 10
SCAN_CHARS = 30000   # the start of a file is enough to tell what it is about

LAYERS_STEP2 = ("Auth", "Config", "Database")
LAYERS_STEP3 = ("API", "Frontend")

_NAME_WORDS = {
    "Auth": ["auth", "login", "session", "password", "token", "jwt", "oauth", "signin", "signup", "sign-in", "sign-up",
             "account", "passport", "clerk", "guard", "permission", "role"],
    "Config": [".env", "config", "setting", "dockerfile", "procfile", "vite.", "next.config", "nuxt.config",
               "tsconfig", "railway", "vercel", "netlify", "wrangler"],
    "Database": ["supabase", "database", "db", "schema", "prisma", "migration", "model", "drizzle", "orm", "sql",
                 "store", "repository"],
    "API": ["route", "api", "server", "main.py", "app.py", "endpoint", "handler", "controller", "webhook", "view"],
    "Frontend": [],
}
_NAME_EXTS = {
    "Config": (".toml", ".ini", ".cfg", ".yaml", ".yml", ".env"),
    "Database": (".sql",),
    "Frontend": (".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm", ".css", ".scss", ".astro"),
}

_I = re.IGNORECASE
_SIGNALS = {
    "Auth": re.compile(
        r"(?:password|passwd|login|logout|log_in|sign[_ -]?in|sign[_ -]?up|session|jwt|oauth|bcrypt|argon2|scrypt|"
        r"pbkdf2|hmac|csrf|cookie|current_user|login_required|isauthenticated|auth\.|getuser|getsession|passport|"
        r"nextauth|clerk|magic[_ -]?link|otp|api[_ -]?key|bearer|authorization|unauthori[sz]ed|forbidden|"
        r"is_admin|isadmin|permission)", _I),
    "Config": re.compile(
        r"(?:os\.getenv|os\.environ|getenv\(|process\.env|import\.meta\.env|dotenv|load_dotenv|settings\.|"
        r"config\[|app\.config|environ\.get|secret_key|debug\s*=|cors|allowed_hosts|port\s*=)", _I),
    "Database": re.compile(
        r"(?:supabase|sqlalchemy|psycopg|sqlite|mongo|prisma|drizzle|knex|sequelize|\.table\(|create\s+table|"
        r"insert\s+into|select\s+[\w*,\s.]+\s+from|\.from\(|\.insert\(|\.upsert\(|\.rpc\(|row[_ ]level|"
        r"postgres|migration|cursor\(|execute\()", _I),
    "API": re.compile(
        r"(?:@app\.route|@router\.|@bp\.|app\.(?:get|post|put|delete|patch|use)\(|router\.(?:get|post|put|delete)|"
        r"fastapi|flask|express\(|jsonify|request\.(?:json|form|args|headers)|req\.(?:body|params|query)|"
        r"nextresponse|export\s+async\s+function\s+(?:get|post|put|delete)|handler\(|status\s*=\s*\d{3}|"
        r"serve\(|\.listen\()", _I),
    "Frontend": re.compile(
        r"(?:document\.|window\.|queryselector|addeventlistener|innerhtml|usestate|useeffect|react|classname=|"
        r"<div|<button|<form|<input|\.style\.|fetch\(|localstorage|getelementbyid|render\()", _I),
}

_MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "pipfile", "go.mod", "gemfile",
              "composer.json", "cargo.toml")

_LEAVE_OUT = ("node_modules/", "/vendor/", "/dist/", "/build/", ".min.", "package-lock", "yarn.lock", "pnpm-lock",
              "poetry.lock", "bun.lock", "/.next/", ".map")
_DOC_EXTS = (".md", ".txt", ".rst", ".license")
_TEST_BITS = (".test.", ".spec.", "/test/", "/tests/", "/__tests__/", "test_", "_test.")


def enabled():
    return os.getenv("VERILAY_LAYER_FILES", "") != "old"


def _skip(path):
    low = path.lower()
    return any(b in low for b in _LEAVE_OUT) or low.endswith(_DOC_EXTS) or low.split("/")[-1].startswith("license")


def score(layer, path, text):
    """How strongly this file belongs to the layer: 0 means not at all."""
    low = path.lower()
    name = low.split("/")[-1]
    if _skip(path):
        return 0.0
    s = 0.0
    if any(w in low for w in _NAME_WORDS.get(layer, [])):
        s += 4
    if name.endswith(_NAME_EXTS.get(layer, ())):
        s += 4 if layer != "Frontend" else 5
    sample = (text or "")[:SCAN_CHARS]
    rx = _SIGNALS.get(layer)
    if rx and sample:
        hits = rx.findall(sample)
        if hits:
            distinct = len({h.lower() for h in hits})
            density = len(hits) / max(len(sample) / 10000.0, 1.0)
            s += 2 * min(distinct, 6) + min(density, 6)
    if s and any(t in low for t in _TEST_BITS):
        s -= 6
    return max(s, 0.0)


def rank(files, layer):
    """[(score, path)] best first, only files that belong to the layer at all."""
    out = [(score(layer, p, t), p) for p, t in files.items()]
    out = [(s, p) for s, p in out if s > 0]
    out.sort(key=lambda sp: (-sp[0], sp[1]))
    return out


def pick(files, layers, manifests=False, legacy_words=()):
    """Paths to show the AI for these layers: the best few per layer, merged, best first, at most MAX_FILES.
    Every layer keeps its top file even when another layer's files score higher. Any slots left over go to files
    the old name-only rule would have picked (legacy_words), so nothing it used to show is lost."""
    chosen, seen = [], set()
    ranked = {L: rank(files, L) for L in layers}
    if manifests:   # the dependency list, so the Libraries part has something to read
        for p in files:
            if p.lower().split("/")[-1] in _MANIFESTS and p not in seen:
                chosen.append(p); seen.add(p)
    for L in layers:   # each layer's best file first
        for s, p in ranked[L][:1]:
            if p not in seen:
                chosen.append(p); seen.add(p)
    rest = []
    for L in layers:
        rest += [(s, p) for s, p in ranked[L][:FILES_PER_LAYER] if p not in seen]
    rest.sort(key=lambda sp: (-sp[0], sp[1]))
    for s, p in rest:
        if p not in seen:
            chosen.append(p); seen.add(p)
    chosen = chosen[:MAX_FILES]
    if legacy_words and len(chosen) < MAX_FILES:
        for p in files:
            if len(chosen) >= MAX_FILES:
                break
            if p not in seen and not _skip(p) and any(w in p.lower() for w in legacy_words):
                chosen.append(p); seen.add(p)
    return chosen
