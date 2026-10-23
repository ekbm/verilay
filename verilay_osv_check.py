"""
verilay_osv_check.py — deterministic dependency vulnerability checking for Verilay.

Same idea as verilay_secret_scan.py: no LLM, no variance, and the buyer can
independently verify every result (OSV.dev is a public, well-known database).
This is Decision 2's #1-ranked reason the $19 tier earns itself, and per
Decision 6 it also runs during the FREE scan as a live teaser.

How it works:
  1. Find manifest/lockfile files in the repo (currently: npm and PyPI).
  2. Extract {name, version} pairs. Prefer lockfiles (exact resolved
     versions) over manifests (version RANGES like ^1.2.3, which can't be
     queried precisely) — this sidesteps the semver-range-parsing problem
     flagged in DEEP-SCAN-DESIGN.md as the fiddly part, rather than solving
     it. For npm, a manifest-only fallback strips the range operator and
     queries the base version when no lockfile is present — imprecise but
     still useful, since real npm projects almost always commit a lockfile
     anyway. For PyPI there is no equivalent lockfile to prefer, so an
     unpinned requirements.txt line (anything but ==) is skipped rather than
     guessed at — querying the floor of a range like flask>=3.0.0 as if it
     were the real installed version produced a 100% false-positive rate in
     practice (see _pypi_requirements_deps), which is worse than reporting
     nothing.
  3. One batch call to OSV.dev (free, no key) — it does the version-range
     matching server-side, so no semver code is needed here either. The
     batch endpoint returns only {id, modified} per match; a second call per
     unique id fetches the actual summary/severity/fix version.
  4. Findings sorted critical-first, same convention as the secret scanner.

Stdlib + requests only (already a Verilay dependency).

UPDATE 2026-10-23 (found by reading this code against a real alert: Replit listed 180 vulnerabilities in one app, and this check would have
shown a fraction of them):
  * A database that does not answer, or refuses a very large request, used to look exactly like "no known vulnerabilities". Now the
    result says the check could not be completed (coverage scope "unavailable"), and never claims the packages are clean.
  * Details were fetched for only the first 40 advisories, in alphabetical order, one at a time, and the rest were dropped silently.
    Now every advisory is looked up (in parallel, kept for 24 hours), and one whose details cannot be loaded is still listed, with
    unknown severity.
  * The package list is sent in chunks, because the database accepts a limited number of packages per request.
  * More package lists are read: poetry.lock, uv.lock and Pipfile.lock (Python apps from Replit and similar), yarn.lock, pnpm-lock.yaml,
    and Bun's text lockfile bun.lock. (Bun's older binary bun.lockb cannot be read; a report now says so.)
  * Every VERSION of a package is checked, not one per name. A project often holds two versions of the same package (Replit listed
    @xmldom/xmldom 0.8.11 and 0.9.10 separately); only the last one in the file used to be looked at.
  * Lock files are no longer thrown away before this check (the file loader skipped everything ending in ".lock").
  * (24 Oct 2026, Moses) COUNTING: the grade and every headline number count PACKAGES, each package version once at its worst severity,
    not advisories. One old library such as pillow can carry 57 advisories and is fixed by ONE upgrade; counting 57 made a handful of
    upgrades look like a mountain and turned any app with a modest dependency tree into an F. Every advisory is still listed in the
    detailed findings. Dev-only packages still never count.
"""

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

try:                                   # Python 3.11+: reads poetry.lock and uv.lock
    import tomllib
except Exception:                      # pragma: no cover
    tomllib = None

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_TIMEOUT = 20
MAX_DETAIL_LOOKUPS = 500  # a safety ceiling only; anything beyond it is still listed (unknown severity), never dropped
BATCH_SIZE = 300          # packages per request; the database accepts at most 1000, stay well under
DETAIL_WORKERS = 8        # advisory details are fetched this many at a time
DETAIL_CACHE_SECONDS = 24 * 3600   # an advisory's own record rarely changes; the "which packages are affected" answer is NEVER cached
DETAIL_CACHE_MAX = 3000

# Severity ranking used by OSV's database_specific.severity (GitHub Security
# Advisory convention) and our own sort order.
SEVERITY_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4}


@dataclass
class Vulnerability:
    id: str                    # e.g. GHSA-xxxx or PYSEC-2023-74
    aliases: List[str]         # e.g. ["CVE-2020-8203"]
    package: str
    ecosystem: str             # npm | PyPI
    version_found: str
    severity: str              # critical | high | moderate | low | unknown
    summary: str
    fixed_version: Optional[str]
    plain: str                 # plain-English one-liner for non-developers
    action: str
    is_dev: bool = False       # True only when CONFIRMED dev/build-tool-only —
                                # see extract_dependencies(). Unknown defaults to
                                # False (counts toward risk) — never hide a real
                                # finding behind an uncertain classification.


# ── Manifest / lockfile parsing ─────────────────────────────────────────────

_NPM_RANGE_PREFIX = re.compile(r"^[\^~><=\s]+")
_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+){1,3}(?:[-.][0-9A-Za-z.]+)?")
_UNRESOLVABLE_NPM = ("*", "latest", "x", "next")


def _npm_manifest_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """package.json — version RANGES, not exact. Fallback when no lockfile.
    Returns {name: (version, is_dev)} — is_dev comes straight from which of
    the two top-level keys the entry was declared under. This only ever
    covers DIRECT dependencies; it cannot see whether a transitive package
    is dev-only, which is exactly why the lockfile parser below is preferred
    whenever a lockfile is present."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return {}
    deps: Dict[Tuple[str, str], bool] = {}
    for key in ("dependencies", "devDependencies"):
        is_dev_key = (key == "devDependencies")
        for name, spec in (data.get(key) or {}).items():
            if not isinstance(spec, str):
                continue
            spec = spec.strip()
            if spec in _UNRESOLVABLE_NPM or spec.startswith(("git", "http", "file:", "workspace:", "link:")):
                continue
            stripped = _NPM_RANGE_PREFIX.sub("", spec)
            m = _VERSION_TOKEN.match(stripped)
            if m:
                # A name listed under both keys (unusual but possible) reaches
                # production via the "dependencies" copy — never let a dev
                # declaration hide that.
                _set_dep(deps, name, m.group(0), is_dev_key)
    return deps


def _npm_lockfile_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """package-lock.json — exact RESOLVED versions, plus each entry's own
    `dev` flag. Preferred source when present. Handles both v1 ("dependencies")
    and v2/v3 ("packages") shapes.

    The `dev` flag matters far more here than in the manifest fallback above:
    npm computes it per RESOLVED package, including every transitive one, so
    it is the only reliable way to know a nested dependency (e.g. a lint
    tool's own sub-dependency) never reaches production — package.json's
    top-level keys only describe DIRECT dependencies (found via a real
    Loginsight scan, 2026-09-15: 12 of 17 High-severity findings were on
    transitive packages that only the lockfile's flag correctly identifies
    as dev-only)."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return {}
    deps: Dict[Tuple[str, str], bool] = {}
    if "packages" in data:  # lockfile v2/v3
        for path, info in data["packages"].items():
            if not path or not isinstance(info, dict):
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if not (name and version):
                continue
            is_dev = bool(info.get("dev"))
            # The SAME package name can resolve at multiple nesting levels —
            # e.g. a dev tool's own copy of minimatch alongside a different,
            # production-reachable copy pulled in elsewhere. If ANY occurrence
            # is NOT dev-only, the package reaches production overall; never
            # let one dev-only copy mask a real prod-facing one under the
            # same name.
            _set_dep(deps, name, version, is_dev)
    elif "dependencies" in data:  # lockfile v1: nested "dependencies" hold other versions of the same package
        def walk(block):
            for name, info in (block or {}).items():
                if isinstance(info, dict):
                    if info.get("version"):
                        _set_dep(deps, name, info["version"], bool(info.get("dev")))
                    walk(info.get("dependencies"))
        walk(data["dependencies"])
    return deps


_PY_LINE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|~=|>=|<=|>|<)?\s*([0-9][0-9A-Za-z.\-]*)?"
)


def _pypi_requirements_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """requirements.txt. Only truly PINNED (==) versions are used.

    Unlike npm, Python projects almost never commit a lockfile with the
    actual resolved versions, so there's no accurate fallback to prefer the
    way extract_dependencies() prefers package-lock.json over package.json.
    That means a range like 'flask>=3.0.0' has no exact-version signal to
    query at all -- treating the floor of the range as if it were what's
    actually installed produced a 100% false-positive rate on Verilay's own
    requirements.txt (every one of its 7 unpinned deps flagged "vulnerable"
    against old floor versions, while the real installed versions were all
    clean). Skipping unpinned lines entirely -- same treatment a bare
    'requests' with no version at all already got -- is less coverage but
    means every finding this DOES report is real, not a guess dressed up as
    a fact.

    is_dev is always False here — a flat requirements.txt carries no dev/prod
    signal the way an npm lockfile does (no separate dev-requirements.txt
    convention is handled), so every PyPI dependency counts toward risk.
    Defaulting to "counts" rather than guessing "safe" is deliberate."""
    deps: Dict[Tuple[str, str], bool] = {}
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PY_LINE.match(line)
        if not m:
            continue
        name, op, version = m.groups()
        if name and version and op == "==":
            _set_dep(deps, name, version, False)
    return deps


def _set_dep(deps, name, version, is_dev):
    """Record one package at one exact version. If ANY copy of that package version is not dev-only, it counts as reaching production."""
    key = (name, version)
    prev = deps.get(key)
    deps[key] = (prev and is_dev) if prev is not None else is_dev


def _toml_packages(content: str) -> list:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []
    pk = data.get("package") if isinstance(data, dict) else None
    return pk if isinstance(pk, list) else []


def _poetry_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """poetry.lock (Python): every package with its exact resolved version. Older files mark dev tools with category = "dev"."""
    deps: Dict[Tuple[str, str], bool] = {}
    for p in _toml_packages(content):
        if not isinstance(p, dict):
            continue
        name, version = p.get("name"), p.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            _set_dep(deps, name, version, p.get("category") == "dev")
    return deps


def _uv_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """uv.lock (Python, the Replit default): exact versions. The project itself and local packages are left out; dev status is unknown."""
    deps: Dict[Tuple[str, str], bool] = {}
    for p in _toml_packages(content):
        if not isinstance(p, dict):
            continue
        name, version = p.get("name"), p.get("version")
        src = p.get("source")
        if isinstance(src, dict) and any(k in src for k in ("editable", "virtual", "directory", "path")):
            continue
        if isinstance(name, str) and isinstance(version, str) and name and version:
            _set_dep(deps, name, version, False)
    return deps


def _pipfile_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """Pipfile.lock (Python): "default" is what ships, "develop" is tooling."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return {}
    deps: Dict[Tuple[str, str], bool] = {}
    if not isinstance(data, dict):
        return deps
    for section, is_dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            v = info.get("version") if isinstance(info, dict) else None
            if isinstance(v, str) and v.startswith("==") and len(v) > 2:
                _set_dep(deps, name, v[2:], is_dev)
    return deps


_YARN_HEADER = re.compile(r'^"?((?:@[^/@"\s]+/)?[^@"\s,:]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """yarn.lock, classic and Berry formats. Dev status is not recorded in this file, so every package counts."""
    deps: Dict[Tuple[str, str], bool] = {}
    name = None
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            m = _YARN_HEADER.match(line.strip())
            name = m.group(1) if (m and line.rstrip().endswith(":") and "@workspace:" not in line) else None
            continue
        if name:
            m = _YARN_VERSION.match(line)
            if m:
                if not m.group(1).startswith("0.0.0-use.local"):
                    _set_dep(deps, name, m.group(1), False)
                name = None
    return deps


_PNPM_NEW = re.compile(r"^  '?/?((?:@[^/@'\s]+/)?[^@'\s/]+)@(\d[^:'\s(]*)")
_PNPM_V5 = re.compile(r"^  '?/((?:@[^/'\s]+/)?[^/'\s]+)/(\d[^:_'\s(]*)")


def _pnpm_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """pnpm-lock.yaml: the "packages" section lists name and exact version. Dev status is not read, so every package counts."""
    deps: Dict[Tuple[str, str], bool] = {}
    in_packages = False
    for line in content.splitlines():
        if line and not line.startswith((" ", "\t", "#")):
            in_packages = line.strip().rstrip(":") == "packages"
            continue
        if not in_packages:
            continue
        m = _PNPM_NEW.match(line) or _PNPM_V5.match(line)
        if m:
            _set_dep(deps, m.group(1), m.group(2), False)
    return deps


def _bun_lock_deps(content: str) -> Dict[Tuple[str, str], bool]:
    """bun.lock (Bun's text lockfile): each entry in "packages" starts with "name@version". Workspace, git, file and alias entries are
    left out. Dev status is not recorded per package, so every package counts."""
    try:
        data = json.loads(re.sub(r",(\s*[}\]])", r"\1", content))     # the file allows trailing commas
    except (json.JSONDecodeError, TypeError):
        return {}
    deps: Dict[Tuple[str, str], bool] = {}
    pk = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(pk, dict):
        return deps
    for _key, val in pk.items():
        spec = val[0] if isinstance(val, list) and val and isinstance(val[0], str) else None
        m = re.match(r"^(@[^/@]+/[^@]+|[^@]+)@(.+)$", spec or "")
        if m and re.match(r"^\d", m.group(2)):
            _set_dep(deps, m.group(1), m.group(2), False)
    return deps


# path suffix -> (parser, ecosystem, is_lockfile)
_MANIFEST_PARSERS: List[Tuple[str, callable, str, bool]] = [
    ("package-lock.json", _npm_lockfile_deps, "npm", True),
    ("yarn.lock", _yarn_lock_deps, "npm", True),
    ("pnpm-lock.yaml", _pnpm_lock_deps, "npm", True),
    ("bun.lock", _bun_lock_deps, "npm", True),
    ("package.json", _npm_manifest_deps, "npm", False),
    ("poetry.lock", _poetry_lock_deps, "PyPI", True),
    ("uv.lock", _uv_lock_deps, "PyPI", True),
    ("Pipfile.lock", _pipfile_lock_deps, "PyPI", True),
    ("requirements.txt", _pypi_requirements_deps, "PyPI", False),
]


def extract_dependencies(files: Dict[str, str]) -> Dict[Tuple[str, str, str], bool]:
    """Returns {(name, ecosystem, version): is_dev}. A package that appears in a lock file is taken from the lock file, with EVERY exact
    version it lists (a project can hold several versions of one package). A package only named in package.json / requirements.txt
    is taken from there. Lock files also carry the only reliable dev/prod signal for packages that other packages pull in."""
    from_manifest: Dict[Tuple[str, str, str], bool] = {}
    from_lockfile: Dict[Tuple[str, str, str], bool] = {}
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        fname = path.rsplit("/", 1)[-1]
        for suffix, parser, ecosystem, is_lockfile in _MANIFEST_PARSERS:
            if fname != suffix:
                continue
            target = from_lockfile if is_lockfile else from_manifest
            for (name, version), is_dev in parser(content).items():
                key = (name, ecosystem, version)
                prev = target.get(key)
                target[key] = (prev and is_dev) if prev is not None else is_dev

    locked_names = {(name, eco) for (name, eco, _v) in from_lockfile}
    merged = {k: d for k, d in from_manifest.items() if (k[0], k[1]) not in locked_names}
    merged.update(from_lockfile)
    return merged



# ── What part of the package list was actually read (2026-10-13) ─────────────
# "N packages checked" used to read as "everything was checked". It is only true when a
# full lockfile (the complete list, including the packages your packages depend on) was
# read. Without one, only the packages named in package.json / requirements.txt are seen.
# This records which case applies so every report can say so in plain words.

class FindingList(list):
    """A plain list of Vulnerability objects that also remembers what the check covered
    (see dependency_coverage). Everything that already passes the findings list around
    can read `.coverage`, so no function signature had to change."""
    coverage = None


def _dir_covers(lock_dir: str, manifest_dir: str) -> bool:
    """A lockfile covers a package.json in the same folder or in any folder below it
    (one root lockfile serves a whole monorepo)."""
    return lock_dir == "" or manifest_dir == lock_dir or manifest_dir.startswith(lock_dir + "/")


def _pypi_unpinned_count(content: str) -> int:
    """requirements.txt lines that name a package without an exact (==) version.
    They are skipped on purpose (see _pypi_requirements_deps), so say how many."""
    n = 0
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PY_LINE.match(line)
        if m and m.group(1) and not (m.group(2) == "==" and m.group(3)):
            n += 1
    return n


def dependency_coverage(files: Dict[str, str]) -> dict:
    """How much of the app's package list the check could read. Never raises.

    scope: "full" (a complete lockfile for everything), "partial" (some folders only, or a
    mix), "direct" (only package.json: the packages named directly), "listed" (only a
    requirements.txt, exact-version lines only), "none" (nothing to check), or "unknown"."""
    try:
        locks: Dict[str, Dict[str, str]] = {}
        mans: Dict[str, Dict[str, str]] = {}
        unreadable = unpinned = binary_locks = 0
        for path, content in files.items():
            if not isinstance(content, str):
                continue
            folder, _, fname = path.rpartition("/")
            if fname == "bun.lockb":
                binary_locks += 1
            for suffix, parser, eco, is_lock in _MANIFEST_PARSERS:
                if fname != suffix:
                    continue
                got = parser(content)
                if is_lock:
                    if got:
                        locks.setdefault(eco, {})[folder] = fname
                    else:
                        unreadable += 1   # present but empty or cut off: say so, do not pretend
                else:
                    if got:
                        mans.setdefault(eco, {})[folder] = fname
                    if eco == "PyPI":
                        unpinned += _pypi_unpinned_count(content)
        ecos = []
        for eco in sorted(set(locks) | set(mans)):
            lk, mn = locks.get(eco, {}), mans.get(eco, {})
            if lk:
                gaps = [m for m in mn if not any(_dir_covers(l, m) for l in lk)]
                scope, source = ("partial" if gaps else "full"), ", ".join(sorted(set(lk.values())))
            elif eco == "PyPI":
                scope, source = "listed", "requirements.txt"
            else:
                scope, source = "direct", "package.json"
            ecos.append({"ecosystem": eco, "scope": scope, "source": source})
        scopes = {e["scope"] for e in ecos}
        if not scopes:
            overall = "none"
        elif scopes == {"full"}:
            overall = "full"
        elif scopes == {"listed"}:
            overall = "listed"
        elif scopes <= {"direct", "listed"}:
            overall = "direct"
        else:
            overall = "partial"
        return {"scope": overall, "ecosystems": ecos, "unpinned_skipped": unpinned, "unreadable_lockfiles": unreadable,
                "binary_locks": binary_locks if overall != "full" else 0}
    except Exception:
        return {"scope": "unknown", "ecosystems": [], "unpinned_skipped": 0, "unreadable_lockfiles": 0, "binary_locks": 0}


def coverage_summary(coverage: Optional[dict], packages_checked: int) -> dict:
    """Plain-English wording for a coverage record: {scope, summary, note}. One place, so the
    live page, the saved report, the IT pack and the AI prompts can never disagree. Reports
    saved before this existed have no coverage: they get a neutral "N packages" with no claim
    of completeness."""
    n = int(packages_checked or 0)
    pk = f"{n} package" + ("" if n == 1 else "s")
    scope = (coverage or {}).get("scope") or "unknown"
    extra = " A package list file was found but could not be read." if (coverage or {}).get("unreadable_lockfiles") else ""
    if (coverage or {}).get("binary_locks"):
        extra += (" A bun.lockb file was found, but it is a binary format Verilay cannot read. To check the full list, add a package-lock.json "
                  "(run: npm install --package-lock-only) or save Bun's text lockfile (run: bun install --save-text-lockfile).")
    if scope == "unavailable":
        return {"scope": scope, "summary": "0 packages checked",
                "note": "The public vulnerability database did not answer, so none of your packages could be checked. "
                        "This is not a clean result. Run the scan again later."}
    more = ""
    if (coverage or {}).get("incomplete"):
        more += " The vulnerability database did not answer for part of this check, so more known problems may exist. Run the scan again later."
    dm = int((coverage or {}).get("details_missing") or 0)
    if dm:
        more += (f" For {dm} known problem{'s' if dm != 1 else ''} the details could not be loaded, so "
                 f"{'it is' if dm == 1 else 'they are'} listed with unknown severity.")
    if scope == "full":
        return {"scope": scope, "summary": f"{pk}, including the ones your packages depend on", "note": more.strip()}
    if scope == "direct":
        return {"scope": scope, "summary": f"{pk} you installed directly",
                "note": "The packages these depend on were not checked, because no full package list was found in the files Verilay read." + extra + more}
    if scope == "listed":
        k = int((coverage or {}).get("unpinned_skipped") or 0)
        skipped = f" ({k} without an exact version {'was' if k == 1 else 'were'} skipped)" if k else ""
        return {"scope": scope, "summary": f"{pk} listed in requirements.txt",
                "note": f"Only entries with an exact version number were checked{skipped}. The packages these depend on were not checked." + extra + more}
    if scope == "partial":
        return {"scope": scope, "summary": f"{pk} (part of the project only)",
                "note": "Only some of the package lists were complete, so for part of the project only the packages named directly were checked, not the ones they depend on." + extra}
    if scope == "none":
        return {"scope": scope, "summary": "0 packages", "note": "No package list with packages in it was found, so nothing was checked." + extra}
    return {"scope": "unknown", "summary": pk, "note": ""}


def _coverage_of(vulns, packages_checked: int) -> dict:
    return coverage_summary(getattr(vulns, "coverage", None), packages_checked)


def _scope_sentence(vulns, packages_checked: int) -> str:
    """Tells the AI exactly what was covered, so its write-up cannot say 'all your dependencies'."""
    cs = _coverage_of(vulns, packages_checked)
    if cs["scope"] in ("full", "unknown"):
        return f" NOTE: {cs['note']} Say this plainly in the Libraries write-up." if cs["note"] else ""
    return (f" SCOPE: only {cs['summary']} were checked. {cs['note']} Say this plainly in the Libraries write-up. "
            "Never describe it as all of the app's dependencies or every library.")


# ── OSV.dev queries ─────────────────────────────────────────────────────────

class _Matches(dict):
    """{(name, ecosystem): [advisory ids]} that also remembers whether EVERY request was answered. A plain dict (as tests supply)
    counts as complete."""
    complete = True


def _post_chunk(queries):
    """One request for up to BATCH_SIZE packages: the list of results, or None when the database did not give a usable answer.
    One retry, because a single dropped connection should not make a whole scan unreadable."""
    for _attempt in (1, 2):
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=OSV_TIMEOUT)
            if resp.status_code >= 500:
                continue
            resp.raise_for_status()
            results = resp.json().get("results")
            if isinstance(results, list) and len(results) == len(queries):
                return results
            return None
        except (requests.RequestException, ValueError, AttributeError):
            continue
    return None


def _query_batch(deps: Dict[Tuple[str, str, str], bool]) -> Dict[Tuple[str, str, str], List[str]]:
    """Which advisories affect which packages. Sent in chunks. Returns {(name, ecosystem, version): [vuln_id, ...]}; the result's
    .complete is False when any chunk could not be answered, so the caller never reads silence as "all clear"."""
    out = _Matches()
    if not deps:
        return out
    keys = list(deps.keys())
    queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version}
               for (name, ecosystem, version) in deps.keys()]
    for i in range(0, len(keys), BATCH_SIZE):
        results = _post_chunk(queries[i:i + BATCH_SIZE])
        if results is None:
            out.complete = False
            continue
        for key, result in zip(keys[i:i + BATCH_SIZE], results):
            r = result if isinstance(result, dict) else {}
            ids = [v["id"] for v in (r.get("vulns") or []) if isinstance(v, dict) and v.get("id")]
            if ids:
                out[key] = ids
            if r.get("next_page_token"):
                out.complete = False          # more results exist than this answer carried
    return out


class _Details(dict):
    """{advisory id: its record} that also lists the ids whose record could NOT be loaded (.missing)."""
    missing = ()


_DETAIL_CACHE: Dict[str, Tuple[float, dict]] = {}
_DETAIL_LOCK = threading.Lock()


def clear_detail_cache():
    with _DETAIL_LOCK:
        _DETAIL_CACHE.clear()


def _cache_get(vid, now):
    with _DETAIL_LOCK:
        hit = _DETAIL_CACHE.get(vid)
        if hit and now - hit[0] < DETAIL_CACHE_SECONDS:
            return hit[1]
        if hit:
            del _DETAIL_CACHE[vid]
    return None


def _cache_put(vid, data, now):
    with _DETAIL_LOCK:
        if len(_DETAIL_CACHE) >= DETAIL_CACHE_MAX:
            _DETAIL_CACHE.clear()             # simple and safe: a cache that never grows without end
        _DETAIL_CACHE[vid] = (now, data)


def _get_one(vid):
    """One advisory's record, or None. One retry for a dropped connection or a busy answer; a plain "not found" is final."""
    for _attempt in (1, 2):
        try:
            resp = requests.get(OSV_VULN_URL.format(id=vid), timeout=OSV_TIMEOUT)
            if resp.ok:
                data = resp.json()
                if isinstance(data, dict):
                    return data
            elif resp.status_code < 500 and resp.status_code != 429:
                return None
        except (requests.RequestException, ValueError):
            pass
    return None


def _fetch_details(vuln_ids: List[str]) -> Dict[str, dict]:
    """The record of every advisory, fetched several at a time and kept for 24 hours. Nothing is dropped: an id whose record cannot
    be loaded (or that lies beyond MAX_DETAIL_LOOKUPS) is listed in .missing, and the caller still reports it."""
    out = _Details()
    missing = []
    now = time.time()
    todo = []
    for vid in vuln_ids:
        hit = _cache_get(vid, now)
        if hit is not None:
            out[vid] = hit
        else:
            todo.append(vid)
    look, over = todo[:MAX_DETAIL_LOOKUPS], todo[MAX_DETAIL_LOOKUPS:]
    missing.extend(over)
    if look:
        with ThreadPoolExecutor(max_workers=max(1, min(DETAIL_WORKERS, len(look)))) as pool:
            for vid, data in zip(look, pool.map(_get_one, look)):
                if data:
                    out[vid] = data
                    _cache_put(vid, data, now)
                else:
                    missing.append(vid)
    out.missing = missing
    return out


def _severity_of(vuln: dict) -> str:
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.lower() in SEVERITY_ORDER:
        return db_sev.lower()
    # Fall back to a CVSS-derived severity array if present.
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        try:
            base = float(re.search(r"[\d.]+", score).group(0)) if "CVSS" not in score else None
        except (AttributeError, ValueError):
            base = None
        if base is not None:
            if base >= 9.0: return "critical"
            if base >= 7.0: return "high"
            if base >= 4.0: return "moderate"
            return "low"
    return "unknown"


def _vkey(v: str):
    """Numeric sort key for a version string ("4.17.21" -> (4, 17, 21)).
    Good enough to order real-world release numbers; pre-release suffixes are
    ignored, which at worst treats 2.0.0-beta as 2.0.0."""
    core = (v or "").split("-")[0].split("+")[0]
    return tuple(int(x) for x in re.findall(r"\d+", core)[:4])


def _fixed_version(vuln: dict, ecosystem: str, installed: Optional[str] = None) -> Optional[str]:
    """The version that fixes THIS advisory for the version the app actually uses.

    OSV lists every affected range, often one per major line (e.g. fixed in
    2.80.0 for the 2.x line AND 4.59.0 for the 4.x line). This used to return
    the first "fixed" event it met, so an app on rollup 4.24.0 was told to
    update to 2.80.0 -- a downgrade -- and others were sent to needless
    major-version jumps. Now: pick the introduced->fixed pair that contains the
    installed version; failing that, the nearest fixed version above it; and
    never a version at or below what is already installed. Commit-hash (GIT)
    ranges are ignored -- "update to 3f9a2c" is not advice a person can use."""
    pairs = []
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    pairs.append((introduced or "0", event["fixed"]))
                    introduced = None
    if not pairs:
        return None
    if not installed:
        return pairs[0][1]
    cur = _vkey(installed)
    containing = [fx for intro, fx in pairs if _vkey(intro) <= cur < _vkey(fx)]
    if containing:
        return min(containing, key=_vkey)
    above = [fx for _, fx in pairs if _vkey(fx) > cur]
    return min(above, key=_vkey) if above else None


def _dedupe_advisory_ids(vuln_ids: List[str], details: Dict[str, dict]) -> List[str]:
    """OSV commonly returns the SAME underlying vulnerability under two ids for
    a PyPI package — e.g. GHSA-hc5x-x2vx-497g and PYSEC-2026-1433 for one real
    gunicorn issue — because each id's own record lists the other in its
    "aliases". Left alone, that doubles every count a non-developer sees: "14
    vulnerabilities" reads as twice as scary as the 7 real ones. Group ids that
    reference each other via aliases and keep one representative per group —
    preferring whichever has an actual summary (PYSEC entries are often blank)
    and, as a tie-break, a GHSA id since those read better in plain English."""
    groups: List[set] = []
    for vid in vuln_ids:
        vuln = details.get(vid)
        related = {vid, *((vuln or {}).get("aliases") or [])}
        merged = None
        for g in groups:
            if g & related:
                g |= related
                merged = g
                break
        if merged is None:
            groups.append(related)

    representatives = []
    for g in groups:
        candidates = [vid for vid in vuln_ids if vid in g]
        if not candidates:
            continue
        candidates.sort(key=lambda vid: (
            not bool((details.get(vid) or {}).get("summary")),
            not vid.startswith("GHSA-"),
        ))
        representatives.append(candidates[0])
    return representatives


def check_dependencies(files: Dict[str, str]) -> Tuple[List[Vulnerability], int]:
    """Main entry point. Returns (vulnerabilities, packages_checked)."""
    deps = extract_dependencies(files)
    cov = dependency_coverage(files)
    if not deps:
        empty = FindingList()
        empty.coverage = cov
        return empty, 0

    matches = _query_batch(deps)
    complete = getattr(matches, "complete", True)
    if not matches:
        clean = FindingList()
        if not complete:
            # Nothing was answered. That is NOT "no vulnerabilities": say the check could not run, and report no package as checked.
            cov = dict(cov)
            cov["scope"] = "unavailable"
            cov["incomplete"] = True
            clean.coverage = cov
            return clean, 0
        clean.coverage = cov
        return clean, len(deps)
    if not complete:
        cov = dict(cov)
        cov["incomplete"] = True              # some packages were not answered: what follows may be missing known problems

    all_ids = sorted({vid for ids in matches.values() for vid in ids})
    details = _fetch_details(all_ids)
    unloaded = set(getattr(details, "missing", ()) or ())
    if unloaded:
        cov = dict(cov)
        cov["details_missing"] = len(unloaded)

    findings: List[Vulnerability] = []
    for (name, ecosystem, version), is_dev in deps.items():
        package_ids = _dedupe_advisory_ids(matches.get((name, ecosystem, version), []), details)
        for vid in package_ids:
            vuln = details.get(vid)
            if not vuln:
                # Never drop a known problem because its description could not be loaded: list it, severity unknown.
                findings.append(Vulnerability(
                    id=vid, aliases=[], package=name, ecosystem=ecosystem, version_found=version, severity="unknown",
                    summary="Details for this advisory could not be loaded just now.", fixed_version=None,
                    plain=(f"Your app uses {name} version {version}, which has a known, publicly documented security issue ({vid}). "
                           "The database did not return the details this time, so how serious it is, and the fix, are not shown."),
                    action=f"Look up {vid} for what it is and which version of {name} fixes it.", is_dev=is_dev))
                continue
            severity = _severity_of(vuln)
            fixed = _fixed_version(vuln, ecosystem, version)
            action = (
                f"Update {name} to {fixed} or later."
                if fixed else
                f"Check {vid} for a patched version of {name} — none listed yet, may need a workaround."
            )
            dev_note = (
                " This is a development/build tool, not something that ships to your users — "
                "still worth fixing, but it does not put visitors at risk the way a runtime "
                "dependency issue would."
                if is_dev else ""
            )
            findings.append(Vulnerability(
                id=vid,
                aliases=vuln.get("aliases") or [],
                package=name,
                ecosystem=ecosystem,
                version_found=version,
                severity=severity,
                summary=vuln.get("summary") or "No summary available.",
                fixed_version=fixed,
                plain=(
                    f"Your app uses {name} version {version}, which has a known, publicly documented "
                    f"security issue ({vid}). This isn't a guess — it's a named, verifiable record, "
                    f"the same kind of check tools like Snyk and GitHub's own security alerts use."
                    f"{dev_note}"
                ),
                action=action,
                is_dev=is_dev,
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 4), f.package))
    result = FindingList(findings)
    result.coverage = cov
    return result, len(deps)


# ── Handing findings to Claude / the UI — same shape as the secret scanner ──

_UNAVAILABLE_BLOCK = (
    "\n\nDEPENDENCY VULNERABILITY CHECK: could NOT be completed. The public vulnerability database did not answer. "
    "Do not say the dependencies are safe, clean or free of known problems, and do not invent findings. Say plainly in the "
    "Libraries write-up that this check could not run this time and should be run again later.\n\n"
)


def to_prompt_block(vulns: List[Vulnerability], packages_checked: int) -> str:
    """Facts for the prompt. Claude explains and prioritises these — it does not re-detect them."""
    if packages_checked == 0 and (getattr(vulns, "coverage", None) or {}).get("scope") == "unavailable":
        return _UNAVAILABLE_BLOCK
    if packages_checked == 0:
        return (
            "\n\nDEPENDENCY VULNERABILITY CHECK: no dependency manifest (package.json, "
            "requirements.txt) was found to check. Do not invent dependency findings.\n\n"
        )
    noun = "dependency" if packages_checked == 1 else "dependencies"
    if not vulns:
        return (
            f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev): {packages_checked} {noun} checked "
            "against the public OSV.dev vulnerability database. None have known vulnerabilities. This "
            "is authoritative — do not invent dependency findings."
            + _scope_sentence(vulns, packages_checked) + "\n\n"
        )
    lines = [
        f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev) — {packages_checked} {noun} checked against "
        "the public OSV.dev vulnerability database. These are VERIFIED, named, publicly documented "
        "vulnerabilities, not guesses. Include every one at the severity given. Do not invent "
        "additional dependency findings beyond this list. Entries marked (DEV-ONLY) are build/tooling "
        "dependencies that never ship to a real user — mention them as lower-priority housekeeping, "
        "not urgent user-facing risk, and do not let them inflate how alarming the overall write-up "
        "sounds." + _scope_sentence(vulns, packages_checked) + "\n"
    ]
    for v in vulns:
        fix = f", fix: upgrade to {v.fixed_version}" if v.fixed_version else ", no fix published yet"
        dev_tag = " (DEV-ONLY)" if v.is_dev else ""
        lines.append(f"- [{v.severity.upper()}]{dev_tag} {v.package}@{v.version_found} — {v.id}: {v.summary}{fix}")
    lines.append("")
    return "\n".join(lines)


def severity_counts(vulns: List[Vulnerability]) -> Tuple[int, int]:
    """(critical_bucket, warning_bucket) for the grade floor — same idea as the
    secret scanner's scan_critical/scan_warning.

    Two corrections made 2026-09-15, found by running this exact function
    against Loginsight's real dependency tree: it produced "18 critical",
    while Verilay's own OSV data actually shows only 1 finding OSV itself
    rates critical (the rest were 17 High, 20 Moderate, 3 Low):

      1. OSV `high` no longer collapses into Verilay's `critical` bucket —
         it moves to `warning`. A HIGH dependency CVE is still real and still
         reported at HIGH severity in every finding list; it just no longer
         inflates the headline "critical" count the way an actual CRITICAL
         does. The previous critical+high -> critical collapse is exactly
         what turned 1 real critical into 18.
      2. A dependency confirmed dev/build-tool-only (see extract_dependencies
         — covers transitive packages too, via the lockfile's own `dev` flag,
         not just top-level declared ones) never counts toward EITHER bucket.
         It still appears in the findings list and prompt block, just doesn't
         drive the grade, since it doesn't reach a live user or production
         runtime. Unknown/unconfirmed dev status defaults to counting the
         finding — never hide real risk behind an uncertain classification."""
    pk = _by_package(vulns)
    critical = sum(1 for s in pk.values() if s == "critical")
    return critical, len(pk) - critical


def _by_package(vulns: List[Vulnerability]) -> Dict[Tuple[str, str, str], str]:
    """{(ecosystem, package, version): the worst severity found for it}, for findings that count (not dev-only). A package version is one
    thing to fix, however many advisories it carries."""
    out: Dict[Tuple[str, str, str], str] = {}
    for v in _countable(vulns):
        key = (v.ecosystem, v.package, v.version_found)
        cur = out.get(key)
        if cur is None or SEVERITY_ORDER.get(v.severity, 4) < SEVERITY_ORDER.get(cur, 4):
            out[key] = v.severity
    return out


def package_counts(vulns: List[Vulnerability]) -> dict:
    """The numbers every page uses: packages (each version once) that count, split serious / less severe; packages only in build tools;
    and the number of separate advisories behind them. {"counted", "critical", "warnings", "dev_only", "advisories"}"""
    crit, warn = severity_counts(vulns)
    dev = {(v.ecosystem, v.package, v.version_found) for v in vulns if v.is_dev} - set(_by_package(vulns))
    return {"counted": crit + warn, "critical": crit, "warnings": warn, "dev_only": len(dev), "advisories": len(_countable(vulns))}


def _countable(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """Findings that count toward user-facing risk — excludes confirmed
    dev/build-tool-only ones. Shared by severity_counts() and the teaser
    functions below so a "found N vulnerabilities (X serious, Y less severe)"
    sentence always has N == X + Y — a dev-only finding is left out of ALL
    three figures in the free-tier teaser, not just the severity split,
    otherwise the total would look inflated against its own breakdown. Full
    detail (to_report_dict, for paying customers) still lists every finding
    including dev-only ones — this exclusion is about what counts toward the
    headline risk figure, not about hiding anything from someone who paid
    for the full list."""
    return [v for v in vulns if not v.is_dev]


def to_teaser_block(vulns: List[Vulnerability], packages_checked: int) -> str:
    """Decision 6 — the FREE scan runs this check too, but shows a count, not
    package names or CVE ids. Full detail (to_prompt_block) is for the paid
    deep scan once it exists. This block explicitly tells Claude not to name
    specifics, so the teaser can't leak through the layer write-up."""
    noun = "dependency" if packages_checked == 1 else "dependencies"
    if packages_checked == 0 and (getattr(vulns, "coverage", None) or {}).get("scope") == "unavailable":
        return _UNAVAILABLE_BLOCK
    if packages_checked == 0:
        return (
            "\n\nDEPENDENCY VULNERABILITY CHECK: no dependency manifest found to check. "
            "Do not invent dependency findings.\n\n"
        )
    counted = _countable(vulns)
    if not counted:
        return (
            f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev): {packages_checked} {noun} checked "
            "against the public OSV.dev vulnerability database. None have known vulnerabilities "
            "that affect your users (any dev/build-tool-only findings don't count here). "
            "State this plainly as a positive in the Libraries layer."
            + _scope_sentence(vulns, packages_checked) + "\n\n"
        )
    crit, warn = severity_counts(vulns)
    return (
        f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev) — {packages_checked} {noun} checked. "
        f"Found {crit + warn} packages with known vulnerabilities ({crit} with a serious problem, {warn} less severe; "
        f"{len(counted)} separate advisories in all, and one upgrade of a package clears all of that package's advisories) in this "
        "app's dependencies, verified against the public OSV.dev database. This is a FREE-TIER "
        "summary — you know the count and severity split, NOT which specific packages or CVEs. "
        "Report ONLY the count and severity split in the Libraries findings. Do NOT name specific "
        "package names, version numbers, or CVE/GHSA ids — you were not given them, so do not "
        "invent them. End the finding by telling the user a deep scan reveals exactly which "
        "packages need updating and how to fix them." + _scope_sentence(vulns, packages_checked) + "\n\n"
    )


def to_teaser_dict(vulns: List[Vulnerability], packages_checked: int) -> dict:
    """What the FREE report's JSON actually carries — count and severity split
    only, no package names or CVE ids. Pairs with to_teaser_block above; keeps
    the same restraint in the API response as in the prompt, so a curious
    visitor reading the raw response doesn't see what the narrative withholds."""
    pc = package_counts(vulns)
    return {
        "packages_checked": packages_checked,
        "vulnerabilities_found": pc["counted"],      # PACKAGES with a known problem (each version once); the page words it that way
        "advisories_found": pc["advisories"],
        "dev_only_packages": pc["dev_only"],
        "critical": pc["critical"],
        "warnings": pc["warnings"],
        "coverage": _coverage_of(vulns, packages_checked),
    }


def to_report_dict(vulns: List[Vulnerability], packages_checked: int) -> dict:
    """Full shape WITH package/CVE detail — for the paid deep scan once it
    exists. Do not attach this to a free-tier report. Lists EVERY finding,
    including dev-only ones — full transparency for someone who paid for the
    complete list. "critical"/"high" here are literal OSV severity counts for
    display, unrelated to severity_counts()'s grade-floor bucketing (which
    excludes dev-only and moves high out of the critical bucket)."""
    pc = package_counts(vulns)
    return {
        "packages_checked": packages_checked,
        "coverage": _coverage_of(vulns, packages_checked),
        "vulnerabilities_found": pc["counted"],      # packages, each version once (the same number the grade uses)
        "advisories_found": len(vulns),
        "dev_only_packages": pc["dev_only"],
        "critical_packages": pc["critical"],
        "critical": sum(1 for v in vulns if v.severity == "critical"),
        "high": sum(1 for v in vulns if v.severity == "high"),
        "vulnerabilities": [
            {
                "id": v.id, "aliases": v.aliases, "package": v.package,
                "ecosystem": v.ecosystem, "version_found": v.version_found,
                "severity": v.severity, "summary": v.summary,
                "fixed_version": v.fixed_version, "plain": v.plain, "action": v.action,
                "is_dev": v.is_dev,
            }
            for v in vulns
        ],
    }
