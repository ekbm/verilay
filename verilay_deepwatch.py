"""verilay_deepwatch.py: loads the "should you run a deep scan?" logic from the private package verilay_pro (Nov 2026).

On Verilay's own server this module becomes verilay_pro.deepwatch. Without the package (the open-source code run
elsewhere), self-monitoring still works and simply never recommends a deep scan.
"""
import sys

import verilay_pro_loader as _pro

try:
    if not _pro.load():
        raise ImportError(_pro.STATUS.get("error") or "verilay_pro is not available")
    from verilay_pro import deepwatch as _watch
except ImportError:
    _watch = None

if _watch is not None:
    sys.modules[__name__] = _watch
else:
    def categorise(filenames):
        return [], 0

    def head_info(owner, repo, token):
        return None

    def sha_before(owner, repo, token, iso):
        return None

    def compare(owner, repo, token, base_sha, head_sha):
        return {"commits": 0, "files": []}

    def last_deep_scan(sb, repo):
        return None

    def evaluate(now, last_deep, change, new_serious, prev=None):
        return {"active": False, "reasons": [], "signature": "", "since": None, "new_serious": [], "emailed_signature": None}

    def should_email(rec):
        return False
