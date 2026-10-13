"""
verilay_repo_access.py — is this GitHub repository public? (2026-10-13)

Verilay reads GitHub with the owner's own token, and that token can see the owner's PRIVATE repositories.
Before this check, anyone could type the name of one of those private repositories into a free scan, or buy a
deep scan for it, and receive an analysis of private code (summary, file names, findings). The scan itself never
asked whether the repository was public.

Rule now: a visitor, or a buyer, may only analyse a repository that GitHub reports as public. The admin
(a signed-in address on ADMIN_EMAILS) may also analyse private repositories, because those are their own.

Never raises. When GitHub cannot be asked, the answer is "unknown" and callers refuse (fail closed): a
privacy check must never fail open.
"""
import os
import re

import requests

GITHUB_API = "https://api.github.com"
TIMEOUT = 15

PRIVATE_OR_MISSING = "Repo not found or private. Make it public or use ZIP upload."
UNKNOWN = "Could not check this repository right now. Please try again in a minute."
DEEP_SCAN_PUBLIC_ONLY = ("A deep scan can only read public GitHub repositories. Make this repository public, "
                         "or run the free analysis with a ZIP upload instead.")


_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")


def valid_names(owner, repo):
    """GitHub owner and repo names only: no path tricks. "." and ".." match the pattern but are path segments."""
    return bool(_NAME.fullmatch(str(owner)) and _NAME.fullmatch(str(repo)) and str(owner).strip(".") and str(repo).strip("."))


def repo_visibility(owner, repo, token=None):
    """"public", "private", "missing" (GitHub says it does not exist or is not visible) or "unknown"."""
    if not valid_names(owner, repo):
        return "missing"           # never put an odd name into an address
    try:
        token = os.getenv("GITHUB_TOKEN", "") if token is None else token
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "verilay-access-check"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            flag = r.json().get("private")
            # "public" only when GitHub says so explicitly; any other kind of answer is not a repository
            return "private" if flag is True else "public" if flag is False else "unknown"
        if r.status_code == 404:
            return "missing"
        print(f"[repo-access] GitHub {r.status_code} for a visibility check", flush=True)
        return "unknown"
    except Exception as e:
        print(f"[repo-access] visibility check failed: {type(e).__name__}", flush=True)
        return "unknown"


def head_info(owner, repo, token=None):
    """{"sha", "date"} of the newest commit on the default branch, or None. Best effort, never raises."""
    if not valid_names(owner, repo):
        return None
    try:
        token = os.getenv("GITHUB_TOKEN", "") if token is None else token
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "verilay-access-check"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}/commits", headers=headers, params={"per_page": 1}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        c = r.json()[0]
        return {"sha": c["sha"], "date": c["commit"]["committer"]["date"]}
    except Exception:
        return None


def refusal(visibility, allow_private=False):
    """The message to show when a repository may NOT be analysed, or None when it may."""
    if visibility == "public":
        return None
    if visibility == "private" and allow_private:
        return None
    if visibility == "unknown":
        return UNKNOWN
    return PRIVATE_OR_MISSING
