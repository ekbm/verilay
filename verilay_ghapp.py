"""verilay_ghapp.py - talking to GitHub as a read-only GitHub App, for the private-repository beta (2026-10-20).

What this does, and the rules it follows:

  * Verilay is installed by the visitor on ONE account, with READ-ONLY access to code (and the metadata GitHub always includes). There is
    no write permission anywhere. The visitor chooses the repositories; Verilay asks GitHub for a one-hour key limited to the one repository
    being scanned, reads the code once, and then removes its own installation, so the access is gone as soon as the code has been read.
  * The person who comes back from GitHub is checked against the installation they claim (the user-authorization step), so nobody can
    scan an installation that is not theirs by editing an address.
  * No key, token or private key is ever logged, stored in the database, or put in a page. A user token is used once and dropped.
  * Nothing here ever uses Verilay's own GITHUB_TOKEN, which can see the owner's private repositories.
  * Every network call has a timeout and turns any failure into a GhAppError with a short, safe message for the visitor.

Settings (Railway variables). None of these are secrets except the last two:
  VERILAY_PRIVATE_REPOS            "0" off (default), "admin" only a signed-in admin, "1" open to everyone (the beta)
  GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_CLIENT_ID
  GITHUB_APP_CLIENT_SECRET, GITHUB_APP_PRIVATE_KEY   (secrets: set them only in Railway, never in chat or the repository)
  VERILAY_PRIVATE_PER_ACCOUNT_DAY  scans per GitHub account per day (default 2)
  VERILAY_PRIVATE_PER_DAY          scans per day in total (default 20)
"""
import hashlib
import hmac
import os
import re
import time

import requests as http      # a name tests can replace

API = "https://api.github.com"
TIMEOUT = 15
_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
_SLUG = re.compile(r"[A-Za-z0-9-]{1,80}")
_CODE = re.compile(r"[A-Za-z0-9_.~-]{1,300}")


class GhAppError(Exception):
    """A problem to tell the visitor about, in plain words. `detail` is for the server log only (never a secret)."""
    def __init__(self, user_message, detail=""):
        super().__init__(user_message)
        self.user_message = user_message
        self.detail = detail


# ── settings ────────────────────────────────────────────────────────────────

def mode():
    """'off', 'admin' (only a signed-in admin) or 'open' (everyone: the beta)."""
    v = os.getenv("VERILAY_PRIVATE_REPOS", "0").strip().lower()
    if v in ("1", "open", "on", "true", "yes"):
        return "open"
    if v == "admin":
        return "admin"
    return "off"


def settings():
    key = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    key = key.replace("\\n", "\n").strip()          # Railway often stores a key on one line with literal \n
    return {"app_id": os.getenv("GITHUB_APP_ID", "").strip(), "slug": os.getenv("GITHUB_APP_SLUG", "").strip(),
            "client_id": os.getenv("GITHUB_APP_CLIENT_ID", "").strip(), "client_secret": os.getenv("GITHUB_APP_CLIENT_SECRET", "").strip(),
            "private_key": key}


def configured():
    s = settings()
    return bool(all(s.values()) and _SLUG.fullmatch(s["slug"]) and s["app_id"].isdigit())


def _int_env(name, default, lo=0, hi=1000):
    try:
        n = int(os.getenv(name, "").strip())
        return n if lo <= n <= hi else default
    except ValueError:
        return default


def limits():
    return {"per_account_day": _int_env("VERILAY_PRIVATE_PER_ACCOUNT_DAY", 2), "per_day": _int_env("VERILAY_PRIVATE_PER_DAY", 20)}


# ── names ───────────────────────────────────────────────────────────────────

def valid_repo(full_name):
    """'owner/name' with GitHub-shaped parts only (no path tricks). Returns (owner, name) or None."""
    if not isinstance(full_name, str) or full_name.count("/") != 1:
        return None
    owner, name = full_name.split("/")
    if not (_NAME.fullmatch(owner) and _NAME.fullmatch(name)) or not owner.strip(".") or not name.strip("."):
        return None
    return owner, name


def account_hash(github_user_id, secret):
    """A keyed hash of the GitHub account id, for the per-account daily limit. The real id is never stored."""
    return hmac.new(str(secret).encode("utf-8"), f"ghacct|{github_user_id}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]


# ── calls to GitHub ─────────────────────────────────────────────────────────

def _hdrs(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "verilay-private-scan"}


def _call(method, url, **kw):
    try:
        r = getattr(http, method)(url, timeout=TIMEOUT, **kw)
    except Exception as e:                       # includes timeouts and connection errors
        raise GhAppError("Could not reach GitHub just now. Please try again in a minute.", f"{type(e).__name__}")
    return r


def app_jwt(now=None):
    """A short-lived (9 minute) token that proves the request comes from the Verilay GitHub App."""
    s = settings()
    if not configured():
        raise GhAppError("Private repository scanning is not set up yet.", "app not configured")
    try:
        import jwt
    except Exception:
        raise GhAppError("Private repository scanning is not available right now.", "PyJWT missing")
    t = int(now if now is not None else time.time())
    try:
        out = jwt.encode({"iat": t - 60, "exp": t + 540, "iss": s["app_id"]}, s["private_key"], algorithm="RS256")
    except Exception as e:
        raise GhAppError("Private repository scanning is not available right now.", f"jwt {type(e).__name__}")
    return out.decode("ascii") if isinstance(out, bytes) else out


def install_url(state):
    s = settings()
    if not configured() or not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", state):
        raise GhAppError("Private repository scanning is not set up yet.", "bad install url input")
    return f"https://github.com/apps/{s['slug']}/installations/new?state={state}"


def exchange_code(code):
    """Swap the one-time code GitHub sends back for the visitor's own short-lived token. Used once, never stored."""
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        raise GhAppError("GitHub did not confirm your sign-in. Please start again.", "bad code")
    s = settings()
    r = _call("post", "https://github.com/login/oauth/access_token", headers={"Accept": "application/json", "User-Agent": "verilay-private-scan"},
              json={"client_id": s["client_id"], "client_secret": s["client_secret"], "code": code})
    try:
        tok = (r.json() or {}).get("access_token")
    except Exception:
        tok = None
    if r.status_code != 200 or not isinstance(tok, str) or not tok:
        raise GhAppError("GitHub did not confirm your sign-in. Please start again.", f"exchange {r.status_code}")
    return tok


def verify_installation(user_token, installation_id=None):
    """Is this installation one the signed-in GitHub user can really use? Returns (the user's numeric id, the installation id), or raises.

    If GitHub did not send an installation id, the user's own list is used, but only when it holds exactly one installation of
    Verilay: an ambiguous answer is refused, never guessed."""
    want = None
    if installation_id not in (None, ""):
        try:
            want = int(installation_id)
        except (TypeError, ValueError):
            raise GhAppError("We couldn't confirm that connection. Please start again.", "bad installation id")
    ids = []
    for page in (1, 2, 3):
        r = _call("get", f"{API}/user/installations", headers=_hdrs(user_token), params={"per_page": 100, "page": page})
        if r.status_code != 200:
            raise GhAppError("We couldn't confirm that connection. Please start again.", f"installations {r.status_code}")
        items = (r.json() or {}).get("installations") or []
        ids += [i.get("id") for i in items if isinstance(i, dict) and isinstance(i.get("id"), int)]
        if len(items) < 100:
            break
    if want is None:
        if len(ids) != 1:
            raise GhAppError("We couldn't tell which connection to use. Please start again.", f"{len(ids)} installations and none named")
        want = ids[0]
    elif want not in ids:
        raise GhAppError("We couldn't confirm that connection belongs to you. Please start again.", "installation not in the user's list")
    r = _call("get", f"{API}/user", headers=_hdrs(user_token))
    uid = (r.json() or {}).get("id") if r.status_code == 200 else None
    if not isinstance(uid, int):
        raise GhAppError("We couldn't confirm that connection. Please start again.", f"user {r.status_code}")
    return uid, want


def installation_token(installation_id, repo_name=None):
    """A one-hour, read-only key for the installation, limited to one repository when a name is given."""
    body = {"permissions": {"contents": "read", "metadata": "read"}}
    if repo_name:
        if not _NAME.fullmatch(str(repo_name)) or not str(repo_name).strip("."):     # "." and ".." are path steps, not names
            raise GhAppError("That repository name doesn't look right.", "bad repo name")
        body["repositories"] = [repo_name]
    r = _call("post", f"{API}/app/installations/{int(installation_id)}/access_tokens", headers=_hdrs(app_jwt()), json=body)
    tok = (r.json() or {}).get("token") if r.status_code == 201 else None
    if not isinstance(tok, str) or not tok:
        raise GhAppError("GitHub would not give Verilay read access to that repository. Check that it is selected for Verilay and try again.",
                         f"token {r.status_code}")
    return tok


def list_repos(token):
    """The repositories this installation can read: [{'full_name','name','owner','private'}], at most 100."""
    r = _call("get", f"{API}/installation/repositories", headers=_hdrs(token), params={"per_page": 100})
    if r.status_code != 200:
        raise GhAppError("Could not list your repositories. Please try again.", f"repos {r.status_code}")
    out = []
    for it in (r.json() or {}).get("repositories") or []:
        if not isinstance(it, dict):
            continue
        full = it.get("full_name")
        if valid_repo(full):
            out.append({"full_name": full, "name": it.get("name"), "owner": (it.get("owner") or {}).get("login"), "private": bool(it.get("private"))})
    return out


def delete_installation(installation_id):
    """Remove Verilay's access to the account. Best effort: returns True when GitHub says it is gone. Never raises."""
    try:
        r = _call("delete", f"{API}/app/installations/{int(installation_id)}", headers=_hdrs(app_jwt()))
        return r.status_code in (204, 404)
    except Exception:
        return False
