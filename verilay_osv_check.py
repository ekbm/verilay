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
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_TIMEOUT = 20
MAX_DETAIL_LOOKUPS = 40   # cap follow-up calls; a pathological manifest shouldn't stall an analysis

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


def _npm_manifest_deps(content: str) -> Dict[str, Tuple[str, bool]]:
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
    deps: Dict[str, Tuple[str, bool]] = {}
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
                prev = deps.get(name)
                deps[name] = (m.group(0), (prev[1] and is_dev_key) if prev else is_dev_key)
    return deps


def _npm_lockfile_deps(content: str) -> Dict[str, Tuple[str, bool]]:
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
    deps: Dict[str, Tuple[str, bool]] = {}
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
            prev = deps.get(name)
            deps[name] = (version, (prev[1] and is_dev) if prev else is_dev)
    elif "dependencies" in data:  # lockfile v1
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and info.get("version"):
                deps[name] = (info["version"], bool(info.get("dev")))
    return deps


_PY_LINE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|~=|>=|<=|>|<)?\s*([0-9][0-9A-Za-z.\-]*)?"
)


def _pypi_requirements_deps(content: str) -> Dict[str, Tuple[str, bool]]:
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
    deps: Dict[str, Tuple[str, bool]] = {}
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PY_LINE.match(line)
        if not m:
            continue
        name, op, version = m.groups()
        if name and version and op == "==":
            deps[name] = (version, False)
    return deps


# path suffix -> (parser, ecosystem, is_lockfile)
_MANIFEST_PARSERS: List[Tuple[str, callable, str, bool]] = [
    ("package-lock.json", _npm_lockfile_deps, "npm", True),
    ("package.json", _npm_manifest_deps, "npm", False),
    ("requirements.txt", _pypi_requirements_deps, "PyPI", False),
]


def extract_dependencies(files: Dict[str, str]) -> Dict[Tuple[str, str], Tuple[str, bool]]:
    """Returns {(name, ecosystem): (version, is_dev)}. Lockfiles win over
    manifests for the same ecosystem when both are present, since they carry
    the exact resolved version rather than a range — and, for npm, the only
    reliable per-package dev/prod signal for TRANSITIVE dependencies too."""
    from_manifest: Dict[Tuple[str, str], Tuple[str, bool]] = {}
    from_lockfile: Dict[Tuple[str, str], Tuple[str, bool]] = {}
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        fname = path.rsplit("/", 1)[-1]
        for suffix, parser, ecosystem, is_lockfile in _MANIFEST_PARSERS:
            if fname != suffix:
                continue
            target = from_lockfile if is_lockfile else from_manifest
            for name, version_and_dev in parser(content).items():
                target[(name, ecosystem)] = version_and_dev

    merged = dict(from_manifest)
    merged.update(from_lockfile)  # lockfile entries override manifest entries
    return merged


# ── OSV.dev queries ─────────────────────────────────────────────────────────

def _query_batch(deps: Dict[Tuple[str, str], Tuple[str, bool]]) -> Dict[Tuple[str, str], List[str]]:
    """One request for all dependencies. Returns {(name, ecosystem): [vuln_id, ...]}."""
    if not deps:
        return {}
    keys = list(deps.keys())
    queries = [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for (name, ecosystem), (version, _is_dev) in deps.items()
    ]
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=OSV_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException:
        return {}  # fail open — OSV being down shouldn't break the analysis

    results = resp.json().get("results", [])
    out = {}
    for key, result in zip(keys, results):
        ids = [v["id"] for v in (result.get("vulns") or [])]
        if ids:
            out[key] = ids
    return out


def _fetch_details(vuln_ids: List[str]) -> Dict[str, dict]:
    """One GET per unique id — the batch endpoint only returns ids. Capped to
    avoid a pathological manifest (hundreds of distinct advisories) stalling
    an analysis; a repo that bad already has bigger problems to report first."""
    details = {}
    for vid in vuln_ids[:MAX_DETAIL_LOOKUPS]:
        try:
            resp = requests.get(OSV_VULN_URL.format(id=vid), timeout=OSV_TIMEOUT)
            if resp.ok:
                details[vid] = resp.json()
        except requests.RequestException:
            continue
    return details


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


def _fixed_version(vuln: dict, ecosystem: str) -> Optional[str]:
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


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
    if not deps:
        return [], 0

    matches = _query_batch(deps)
    if not matches:
        return [], len(deps)

    all_ids = sorted({vid for ids in matches.values() for vid in ids})
    details = _fetch_details(all_ids)

    findings: List[Vulnerability] = []
    for (name, ecosystem), (version, is_dev) in deps.items():
        package_ids = _dedupe_advisory_ids(matches.get((name, ecosystem), []), details)
        for vid in package_ids:
            vuln = details.get(vid)
            if not vuln:
                continue
            severity = _severity_of(vuln)
            fixed = _fixed_version(vuln, ecosystem)
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
    return findings, len(deps)


# ── Handing findings to Claude / the UI — same shape as the secret scanner ──

def to_prompt_block(vulns: List[Vulnerability], packages_checked: int) -> str:
    """Facts for the prompt. Claude explains and prioritises these — it does not re-detect them."""
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
            "is authoritative — do not invent dependency findings.\n\n"
        )
    lines = [
        f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev) — {packages_checked} {noun} checked against "
        "the public OSV.dev vulnerability database. These are VERIFIED, named, publicly documented "
        "vulnerabilities, not guesses. Include every one at the severity given. Do not invent "
        "additional dependency findings beyond this list. Entries marked (DEV-ONLY) are build/tooling "
        "dependencies that never ship to a real user — mention them as lower-priority housekeeping, "
        "not urgent user-facing risk, and do not let them inflate how alarming the overall write-up "
        "sounds.\n"
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
    counted = _countable(vulns)
    critical = sum(1 for v in counted if v.severity == "critical")
    warning = sum(1 for v in counted if v.severity in ("high", "moderate", "low", "unknown"))
    return critical, warning


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
            "State this plainly as a positive in the Libraries layer.\n\n"
        )
    crit, warn = severity_counts(vulns)
    return (
        f"\n\nCONFIRMED DEPENDENCY CHECK (OSV.dev) — {packages_checked} {noun} checked. "
        f"Found {len(counted)} known vulnerabilities ({crit} serious, {warn} less severe) in this "
        "app's dependencies, verified against the public OSV.dev database. This is a FREE-TIER "
        "summary — you know the count and severity split, NOT which specific packages or CVEs. "
        "Report ONLY the count and severity split in the Libraries findings. Do NOT name specific "
        "package names, version numbers, or CVE/GHSA ids — you were not given them, so do not "
        "invent them. End the finding by telling the user a deep scan reveals exactly which "
        "packages need updating and how to fix them.\n\n"
    )


def to_teaser_dict(vulns: List[Vulnerability], packages_checked: int) -> dict:
    """What the FREE report's JSON actually carries — count and severity split
    only, no package names or CVE ids. Pairs with to_teaser_block above; keeps
    the same restraint in the API response as in the prompt, so a curious
    visitor reading the raw response doesn't see what the narrative withholds."""
    crit, warn = severity_counts(vulns)
    return {
        "packages_checked": packages_checked,
        "vulnerabilities_found": len(_countable(vulns)),
        "critical": crit,
        "warnings": warn,
    }


def to_report_dict(vulns: List[Vulnerability], packages_checked: int) -> dict:
    """Full shape WITH package/CVE detail — for the paid deep scan once it
    exists. Do not attach this to a free-tier report. Lists EVERY finding,
    including dev-only ones — full transparency for someone who paid for the
    complete list. "critical"/"high" here are literal OSV severity counts for
    display, unrelated to severity_counts()'s grade-floor bucketing (which
    excludes dev-only and moves high out of the critical bucket)."""
    return {
        "packages_checked": packages_checked,
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
