"""verilay_pro_loader.py: makes Verilay's private paid code (the verilay_pro package) importable (Nov 2026).

The deep scan engine lives in the private repository ekbm/verilay-pro. On Verilay's own server, Railway holds a
read-only GitHub key in VERILAY_PRO_TOKEN; when the app starts, this downloads the pinned version of the package
from GitHub's normal download link and adds it to the import path. No Railway build settings are involved, so a
problem here can never break a deploy: without the package the free scanner runs as normal and deep scans show as
paused (see verilay_deepscan.py). /platform-health shows whether it loaded (verilay_platformcheck.check_pro_package).

Someone running the open-source code has no key, so nothing is downloaded. The key is only ever sent to GitHub, in a
request header; it is never written to disk or printed.
"""
import io
import os
import re
import sys
import tempfile
import zipfile

PRO_REPO = "ekbm/verilay-pro"
PRO_REF = (os.getenv("VERILAY_PRO_REF", "") or "v0.2.3").strip()    # the version to load: a tag in the private repo
STATUS = {"loaded": False, "how": "", "ref": PRO_REF, "error": ""}
_MEMBER = re.compile(r"^[^/]+/(verilay_pro/[A-Za-z0-9_]+\.py)$")      # only the package's own .py files are unpacked


def _download(token, ref):
    import requests
    r = requests.get(f"https://api.github.com/repos/{PRO_REPO}/zipball/{ref}", timeout=25,
                     headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                              "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "verilay"})
    if r.status_code != 200:
        raise RuntimeError(f"GitHub answered {r.status_code} (check VERILAY_PRO_TOKEN and VERILAY_PRO_REF on Railway)")
    if len(r.content) > 20 * 1024 * 1024:
        raise RuntimeError("the download is unexpectedly large")
    return r.content


def _unpack(blob, ref):
    """Unpack the package into a folder of its own and return that folder. Several app processes start together,
    so each unpacks into a fresh folder and the first finished one is reused by later starts."""
    base = os.path.join(tempfile.gettempdir(), "verilay_pro_" + re.sub(r"[^A-Za-z0-9_.-]", "_", ref))
    if os.path.isfile(os.path.join(base, "verilay_pro", "__init__.py")):
        return base
    work = tempfile.mkdtemp(prefix="verilay_pro_dl_")
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = [n for n in z.namelist() if _MEMBER.match(n)]
        if not any(n.endswith("verilay_pro/__init__.py") for n in names):
            raise RuntimeError("the download does not contain the verilay_pro package")
        for n in names:
            rel = _MEMBER.match(n).group(1)
            os.makedirs(os.path.join(work, "verilay_pro"), exist_ok=True)
            with z.open(n) as src, open(os.path.join(work, *rel.split("/")), "wb") as dst:
                dst.write(src.read(2 * 1024 * 1024))
    try:
        os.replace(work, base)
    except OSError:
        return work if not os.path.isdir(base) else base
    return base


def load():
    """True when verilay_pro can be imported (already installed, or downloaded now)."""
    if STATUS["loaded"]:
        return True
    try:
        import verilay_pro  # noqa: F401  (installed some other way, or a developer's PYTHONPATH)
        STATUS.update(loaded=True, how="installed")
        return True
    except ImportError:
        pass
    token = (os.getenv("VERILAY_PRO_TOKEN", "") or "").strip()
    if not token:
        STATUS.update(error="no VERILAY_PRO_TOKEN on this server")
        return False
    try:
        folder = _unpack(_download(token, PRO_REF), PRO_REF)
        if folder not in sys.path:
            sys.path.insert(0, folder)
        import verilay_pro  # noqa: F401
        STATUS.update(loaded=True, how="downloaded", error="")
        print(f"[pro] verilay_pro {PRO_REF} loaded", flush=True)
        return True
    except Exception as e:
        STATUS.update(error=f"{type(e).__name__}: {str(e)[:200]}")
        print(f"[pro] verilay_pro not loaded: {STATUS['error']}", flush=True)
        return False
