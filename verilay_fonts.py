"""verilay_fonts.py - Verilay's heading font (Fraunces), served from our own server.

Why self-hosted: a visitor's browser never contacts Google just to draw our headings, which matches the
privacy-friendly feel of the rest of the site. The two files in ./fonts are Fraunces Latin, weights 600 and 700,
under the SIL Open Font Licence (the licence text sits beside them in fonts/OFL.txt and must stay with them).

What this module does:
  * serve_font(name)  - returns the bytes of ONE of the two whitelisted files (never any other path).
  * head_html()       - the <link rel=preload> and <style> (@font-face + heading rule) added to a page's <head>.
  * wants_fonts(path) - which pages get it.

Only headings use the font: every <h1>, and anything marked class="vl-display". Body text stays in the visitor's
own system font, and every rule names Georgia / serif as the fallback, so a page still looks right if the font
file ever fails to load.
"""
import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")

FONT_FILES = {
    "fraunces-latin-600-normal.woff2": 600,
    "fraunces-latin-700-normal.woff2": 700,
}

MARK = "vl-fraunces"   # present once the snippet is in a page, so it is never added twice

# Pages that get the heading font. Exact match, or a sub-path of the entries in _PREFIXES.
_EXACT = ("/", "/deep-scan", "/private-repos", "/monitoring", "/apps", "/about", "/blog")
_PREFIXES = ("/blog", "/apps")


def serve_font(name):
    """Bytes of a whitelisted font file, or None. `name` is matched against FONT_FILES, never joined blindly."""
    if name not in FONT_FILES:
        return None
    try:
        with open(os.path.join(_DIR, name), "rb") as fh:
            return fh.read()
    except OSError:
        return None


def wants_fonts(path):
    p = (path or "/").rstrip("/") or "/"
    if p.startswith("/apps/review"):
        return False
    if p in _EXACT or any(p.startswith(x + "/") for x in _PREFIXES):
        return True
    # a finished report page, but not its sub-pages (IT review pack, exports)
    parts = p.split("/")
    return len(parts) == 3 and parts[1] == "report" and bool(parts[2])


def head_html():
    faces = "".join(
        f'@font-face{{font-family:"Fraunces";font-style:normal;font-weight:{w};font-display:swap;'
        f'src:url(/fonts/{n}) format("woff2")}}'
        for n, w in sorted(FONT_FILES.items(), key=lambda kv: kv[1]))
    return (
        f'<!-- {MARK}: heading font, served from this site -->\n'
        '<link rel="preload" href="/fonts/fraunces-latin-700-normal.woff2" as="font" type="font/woff2" crossorigin>\n'
        f'<style id="{MARK}">{faces}'
        'h1,.vl-display{font-family:"Fraunces",Georgia,"Times New Roman",serif;font-weight:700;letter-spacing:-.02em}'
        '</style>\n'
    )
