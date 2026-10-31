"""verilay_deepscan.py: loads the deep scan engine, which lives in the private package verilay_pro (Nov 2026).

On Verilay's own server the private package is downloaded when the app starts (verilay_pro_loader.py), and this
module simply becomes it: `import verilay_deepscan` gives the real engine, so app.py and verilay_paywall.py need no change.

Anywhere else (someone running the open-source code), the package is missing and the small stand-in below is used:
the free scanner works as normal, AVAILABLE is False, and new deep-scan purchases are paused with a plain message,
so nobody can pay for a scan that cannot run.
"""
import sys

import verilay_pro_loader as _pro

try:
    if not _pro.load():
        raise ImportError(_pro.STATUS.get("error") or "verilay_pro is not available")
    from verilay_pro import deepscan as _engine
except ImportError:
    _engine = None

if _engine is not None:
    _engine.AVAILABLE = True
    sys.modules[__name__] = _engine
else:
    AVAILABLE = False
    NOT_AVAILABLE_MESSAGE = ("Deep scans are not available on this server right now. Nothing has been charged. "
                             "Please try again later, or email moses@verilay.dev.")
    INTERRUPTED_MESSAGE = ("This scan was interrupted, most likely because Verilay was updated while it was "
                           "running. No report was saved and nothing was counted against your scans.")
    print("[deepscan] the private verilay_pro package is not installed: deep scans are not available", flush=True)

    def configure(**kwargs):
        return None

    def get_job(job_id):
        return None

    def cancel_job(job_id):
        return False

    def create_job(repo, purchase_id, user_id=None):
        raise RuntimeError(NOT_AVAILABLE_MESSAGE)

    def start_job(job_id, user_id=None):
        return None

    def running_job_count():
        return 0

    def active_job_for_repo(repo):
        return None

    def active_jobs_for_user(user_id):
        return []
