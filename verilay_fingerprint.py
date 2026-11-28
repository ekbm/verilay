"""
verilay_fingerprint.py: does a scanned app contain Verilay's own code? (Moses, 28 Nov 2026)

Verilay's code is public under a licence that allows personal and open-source use but needs a commercial licence for
commercial use (LICENSE.md). People building a copy often test it with the original, so every scan quietly looks for
Verilay's own fingerprints: its header and names and phrases only Verilay uses. When at least two different ones are
found, the scan is flagged on the admin page and the owner gets one email. The visitor sees nothing, the report is not
changed, and nothing is blocked. Verilay's own apps and the accuracy check are never flagged.

Only file names and which markers matched are kept: never the code itself.
"""
import re

MIN_MARKERS = 2       # one shared word is chance; two distinct Verilay-only markers is a copy

# (label, pattern). Specific to Verilay: its header, its licence line, internal names and fixed wording no other tool uses.
MARKERS = (
    ("Verilay header", re.compile(r"Verilay\s+[—-]+\s+AI App Verification Layer", re.I)),
    ("Verilay licence", re.compile(r"#\s*Verilay Licence|Copyright \(c\) 2026 Moses Ekbote", re.I)),
    ("demote_coverage_notes", re.compile(r"\bdemote_coverage_notes\b")),
    ("mark_repeated_findings", re.compile(r"\bmark_repeated_findings\b")),
    ("cap_example_file_findings", re.compile(r"\bcap_example_file_findings\b")),
    ("smart_file_selection", re.compile(r"\bsmart_file_selection\b")),
    ("ASK_VERILAY_REPORT_SYSTEM", re.compile(r"\bASK_VERILAY_REPORT_SYSTEM\b")),
    ("VERILAY_GO_AHEAD", re.compile(r"\bVERILAY_GO_AHEAD\b")),
    ("verilay_ module names", re.compile(r"\bimport\s+verilay_(?:selfcheck|secret_scan|layer_files|glance|compare|deepreport|livecheck|sitecheck)\b")),
    ("Verilay wording", re.compile(r"Treat findings as things to verify, not things to fix", re.I)),
)


def find(files):
    """{'markers': [...], 'files': [...]} when at least MIN_MARKERS different Verilay markers appear, else None.
    `files` is {path: text}. Never raises."""
    try:
        hits, where = [], []
        for path, text in (files or {}).items():
            if not isinstance(text, str):
                continue
            found_here = False
            for label, rx in MARKERS:
                if label not in hits and rx.search(text):
                    hits.append(label)
                    found_here = True
            if found_here and len(where) < 5:
                where.append(str(path)[:120])
        return {"markers": hits, "files": where} if len(hits) >= MIN_MARKERS else None
    except Exception:
        return None
