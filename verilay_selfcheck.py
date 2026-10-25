"""verilay_selfcheck.py - "Check it yourself": a few plain steps a non-developer can try to confirm a finding.

Why this exists: a scanner's finding is a lead, not a verdict (a tester put it well: map every finding to a direct test before
changing any code). Verilay's readers usually cannot run such a test, so each problem type gets a short, free, safe test.

How it works, and the rules it follows:
  * The steps are a FIXED LIBRARY written and reviewed by hand. The AI never writes them. Matching a finding to a check is done
    with plain keyword rules on the finding's title and reason, so the same input always gives the same steps.
  * No match means no steps. Nothing is ever invented to fill a gap.
  * Problem types that cannot be safely tested by a non-developer (server-side request forgery, path traversal, remote code
    execution...) get an honest note instead: "this one needs an experienced person to confirm".
  * Every block says to try it only on your OWN app, with test accounts. No step asks anyone to probe somebody else's site, to
    run anything destructive, or to paste a secret anywhere.
  * Steps are static text, so rendering them can never carry user data into the page.
  * Applied when a page is drawn, so older reports get the steps too (nothing is saved in the report for this).
"""
import re
from html import escape

MAX_PER_FINDING = 2

SAFETY = "Only try this on your own app, with test accounts. Never on someone else's app."

CHECKS = {
    "logged_out": {
        "title": "Does a stranger get in without logging in?", "minutes": 2,
        "steps": ["Open a private (incognito) window, so you're not logged in.",
                  "Paste the address of a page that should need a login, such as your account or dashboard page.",
                  "Press Enter and see what happens."],
        "good": "You're sent to a login page, or told you can't view it.",
        "bad": "The page opens and shows someone's data. Note the exact address and tell your AI builder.",
        "limit": "Hiding a button isn't protection. The data behind a page must also refuse a stranger.",
    },
    "two_accounts": {
        "title": "Can one user see another user's data?", "minutes": 5,
        "steps": ["Make two test accounts with two email addresses you own. Call them A and B.",
                  "As A, create something private, such as a note, an order or a profile detail.",
                  "Log out. Log in as B, using a different browser or a private window.",
                  "Look for A's item. If its page address contains a number (for example /orders/123), paste A's address while logged in as B."],
        "good": "B can't see A's item and gets an error or an empty page.",
        "bad": "B can see it. Note which page and tell your AI builder before real users join.",
        "limit": "If you use Supabase, also check that every table holding user data shows Row Level Security (RLS) switched on.",
    },
    "key_in_browser": {
        "title": "Can a visitor's browser read a secret key?", "minutes": 3,
        "steps": ["Open your live app in Chrome. Right-click the page and choose View page source (or press Ctrl+U).",
                  "Press Ctrl+F and search for words such as secret, service_role, sk- and PRIVATE KEY.",
                  "Optional: press F12, open the Network tab, reload, click each .js file and search the same way."],
        "good": "Nothing like a secret appears. (A Supabase anon key is meant to be public.)",
        "bad": "A real key appears. Treat it as leaked: replace it in the service's own dashboard first, then ask your AI builder to move it to a server-side secret.",
        "limit": "Never paste a real key into a chat, an email or a website while checking.",
    },
    "key_in_repo": {
        "title": "Is a secret saved in your GitHub repository?", "minutes": 3,
        "steps": ["Open your repository on GitHub.",
                  "Open the file and line that Verilay named in this report.",
                  "Decide whether the value is real, or an example or placeholder."],
        "good": "It's an example, a placeholder, or a value that is meant to be public.",
        "bad": "It's a real key. Make a new key in the service's dashboard and switch to it. Deleting the file isn't enough, because the old key stays in the repository's history.",
        "limit": "Never paste a real key into a chat, an email or a website while checking.",
    },
    "old_packages": {
        "title": "Do your packages have known problems?", "minutes": 3,
        "steps": ["On GitHub, open your repository and click Security, then Dependabot alerts. It's free; if it's switched off, it can be turned on under Settings, then Security.",
                  "Or ask a developer friend to run the free command npm audit in your project folder."],
        "good": "No high or critical alerts.",
        "bad": "Alerts are listed. Update the packages they name, then scan again.",
        "limit": "Updating a package can break an app, so update one at a time and test after each.",
    },
    "odd_characters": {
        "title": "Does a strange character break it?", "minutes": 2,
        "steps": ["On your own app, find a search box or a form.",
                  "Type a single apostrophe (') and press Search or Submit.",
                  "Watch what happens."],
        "good": "A normal \"no results\" or a normal, friendly error message.",
        "bad": "A technical error that mentions SQL, a query or the database, or a crash page. Tell your AI builder.",
        "limit": "Seeing nothing wrong doesn't prove it's safe. This only catches the most obvious cases.",
    },
    "typed_html": {
        "title": "Does the page treat what you type as code?", "minutes": 2,
        "steps": ["Find a text box whose content is shown back on a page later, such as a comment, a profile name or a search result.",
                  "Type <b>test</b> and submit it.",
                  "Look at how it appears."],
        "good": "You see the characters exactly as typed: <b>test</b>.",
        "bad": "You see the word test in bold. The page is treating typed text as code. Tell your AI builder.",
        "limit": "Use a test account. Seeing it displayed safely doesn't prove every box is safe.",
    },
    "upload_wrong_file": {
        "title": "Does the upload accept the wrong kind of file?", "minutes": 2,
        "steps": ["Find an upload button on your own app.",
                  "Choose a harmless file of the wrong kind, such as a plain .txt file where only pictures are expected.",
                  "Try to upload it."],
        "good": "The app refuses it with a clear message.",
        "bad": "The app accepts it. Tell your AI builder.",
        "limit": "This only catches the most basic problem. Whether an uploaded file could be dangerous needs an experienced person.",
    },
    "too_many_tries": {
        "title": "Can someone try passwords without limit?", "minutes": 3,
        "steps": ["On your own login page, use a test account.",
                  "Enter a wrong password about ten times in a row.",
                  "Watch for a pause, a \"too many attempts\" message, or a block."],
        "good": "You're slowed down or blocked.",
        "bad": "Every try is accepted, however many. Tell your AI builder.",
        "limit": "Use a test account, not your real one, in case it locks.",
    },
    "headers": {
        "title": "Does the live site send the standard safety headers?", "minutes": 3,
        "steps": ["Go to a free checker such as securityheaders.com and type the address of your own live site.",
                  "Read the grade and the list of missing headers."],
        "good": "The main headers are present.",
        "bad": "Some are missing. Ask your AI builder or your host how to add them. Many are optional.",
        "limit": "These headers are set by your hosting, not in the app's code. Only check your own site.",
    },
    "weak_hash": {
        "title": "What is that old hash used for?", "minutes": 5,
        "steps": ["Open the file Verilay named, on GitHub, and read the few lines around that hash.",
                  "Ask your AI builder: \"Is this hash used for passwords or login tokens anywhere? Review and advise, don't change anything yet.\"",
                  "Read its answer."],
        "good": "It's only used for labels, such as cache keys or file names.",
        "bad": "It protects passwords or login tokens. Move to bcrypt, scrypt or argon2.",
        "limit": "If you use a login service such as Supabase Auth or Clerk, your app may not store passwords at all.",
    },
    "login_token": {
        "title": "Is that login token real?", "minutes": 2,
        "steps": ["Open the file Verilay named, on GitHub.",
                  "Decide whether the value is a test or example, or came from a real logged-in account."],
        "good": "It's a test or example value.",
        "bad": "It's from a real account. Remove it, sign that account out everywhere and change its password.",
        "limit": "Never paste a real token into a chat, an email or a website while checking.",
    },
}

NEEDS_PERSON = ("This one is best confirmed by someone with security experience. It isn't something to test yourself. "
                "Ask your AI builder to explain it, then ask a developer or a security tester to confirm it.")

# Problem types a non-developer cannot safely test: an honest note instead of steps.
_NEEDS_PERSON_RE = re.compile(r"(?i)\bssrf\b|server-side request|path traversal|directory traversal|\bxxe\b|xml external|remote code"
                              r"|\brce\b|command injection|deserializ|prototype pollution|zip slip|sandbox")

# Keyword rules on a finding's title and reason, in priority order. First two matches win.
_FIX_RULES = (
    ("key_in_browser", re.compile(r"(?i)(?:front-?end|browser|client[- ]side|bundle)[^.]{0,60}(?:secret|api key|key|credential|token)"
                                  r"|(?:secret|api key|credential)[^.]{0,60}(?:front-?end|browser|client[- ]side|bundle)")),
    ("key_in_repo", re.compile(r"(?i)private key|hard-?coded|\bsecrets?\b|api key|credentials?\b|\.env\b|committed (?:key|secret)")),
    ("odd_characters", re.compile(r"(?i)sql injection|nosql|\binjection\b")),
    ("typed_html", re.compile(r"(?i)\bxss\b|cross-site scripting|innerhtml|unescaped|unsanitized|dom-based")),
    ("upload_wrong_file", re.compile(r"(?i)file upload|\bupload")),
    ("too_many_tries", re.compile(r"(?i)rate[- ]limit|brute[- ]force|throttl")),
    ("old_packages", re.compile(r"(?i)dependenc|vulnerable (?:package|librar)|outdated (?:package|librar)|known vulnerabilit|\bcves?\b")),
    ("headers", re.compile(r"(?i)security headers?|\bcsp\b|content-security|\bhsts\b|\bcors\b|x-frame")),
    ("weak_hash", re.compile(r"(?i)\bmd5\b|sha-?1\b|weak hash|password hash")),
)
# Broader rules, used ONLY when no specific problem type matched, and then only the first one: "authorization" and "login"
# are mentioned in many findings that are really about something else (for example SQL injection in a login form).
_GENERIC_RULES = (
    ("two_accounts", re.compile(r"(?i)authori[sz]ation|access control|\bidor\b|cross-user|other users?|another user|row[- ]level|\brls\b|privilege|ownership")),
    ("logged_out", re.compile(r"(?i)authenticat|\blogin\b|\bsession\b|\bjwt\b|unsigned|forged|auth bypass|bypass(?:able)? .{0,20}auth|missing auth")),
)
# These types have no test a non-developer can safely run. When one matches, it stands alone, with one exception: a plain
# "file upload" finding keeps the basic wrong-file test next to the note.
_NEVER_WITH_TESTS_RE = re.compile(r"(?i)\bssrf\b|server-side request|path traversal|directory traversal|\bxxe\b|xml external|zip slip")

# The scanner's own rule ids (secret and cryptography checks).
_RULE_CHECKS = {
    "PK001": ["key_in_repo"],
    "SUPA001": ["key_in_repo", "key_in_browser"],
    "SUPA002": ["key_in_repo", "key_in_browser"],
    "JWT001": ["login_token"],
    "CRYPTO001": ["weak_hash"],
    "CRYPTO001-HINT": ["weak_hash"],
}


def checks_for_text(title="", why="", area=""):
    """Check ids for a finding described by its title and reason, at most MAX_PER_FINDING. The id 'needs_person' may be last."""
    text = f"{title or ''} {why or ''}"
    if not text.strip():
        return []
    if _NEVER_WITH_TESTS_RE.search(text):
        return ["needs_person"]
    found = []
    for cid, rx in _FIX_RULES:
        if rx.search(text) and cid not in found:
            found.append(cid)
    if not found:
        for cid, rx in _GENERIC_RULES:
            if rx.search(text):
                found = [cid]
                break
    found = found[:MAX_PER_FINDING]
    if _NEEDS_PERSON_RE.search(text):
        # keep room for the honest note; drop a weaker second check if needed
        found = found[:MAX_PER_FINDING - 1] + ["needs_person"]
    return found


def checks_for_fix(fix):
    if not isinstance(fix, dict):
        return []
    return checks_for_text(fix.get("title"), fix.get("why_it_matters"), fix.get("area"))


def checks_for_rules(rule_ids):
    """Check ids for the scanner rules present, in order, de-duplicated, at most MAX_PER_FINDING."""
    out = []
    for rid in rule_ids or []:
        if not isinstance(rid, str):
            continue
        for cid in _RULE_CHECKS.get(rid.upper(), (["key_in_repo"] if rid.upper().startswith(("SEC", "KEY", "GEN", "AWS", "STRIPE", "TOK")) else [])):
            if cid not in out:
                out.append(cid)
    return out[:MAX_PER_FINDING]


def detail(ids):
    """Plain data for the browser script (static text only)."""
    out = []
    for cid in ids or []:
        if cid == "needs_person":
            out.append({"id": cid, "title": "Needs an experienced person", "note": NEEDS_PERSON})
        elif cid in CHECKS:
            c = CHECKS[cid]
            out.append({"id": cid, "title": c["title"], "minutes": c["minutes"], "steps": list(c["steps"]),
                        "good": c["good"], "bad": c["bad"], "limit": c["limit"]})
    return out


def render(ids):
    """The 'Check it yourself' block as HTML ('' when there is nothing to show). Static text only."""
    items = detail(ids)
    if not items:
        return ""
    minutes = sum(i.get("minutes", 0) for i in items)
    parts = []
    for it in items:
        if it["id"] == "needs_person":
            parts.append(f'<div style="font-size:13px;color:#444;margin:.5rem 0"><strong>{escape(it["title"])}.</strong> {escape(it["note"])}</div>')
            continue
        steps = "".join(f"<li>{escape(s)}</li>" for s in it["steps"])
        parts.append(
            f'<div style="margin:.5rem 0 .75rem"><div style="font-size:13px;font-weight:600">{escape(it["title"])}</div>'
            f'<ol style="font-size:13px;color:#444;line-height:1.55;margin:.3rem 0 .3rem 1.2rem">{steps}</ol>'
            f'<div style="font-size:13px;color:#27500A">&#10003; {escape(it["good"])}</div>'
            f'<div style="font-size:13px;color:#791F1F">&#9888; {escape(it["bad"])}</div>'
            f'<div style="font-size:12px;color:#6b6966;margin-top:.2rem">{escape(it["limit"])}</div></div>')
    when = f" &middot; about {minutes} minute{'' if minutes == 1 else 's'}" if minutes else ""
    return (f'<details class="selfcheck" style="margin:.6rem 0 0;background:#F8F8FC;border-radius:8px;padding:.6rem .8rem">'
            f'<summary style="cursor:pointer;font-size:13px;font-weight:600;color:#534AB7">Check it yourself{when}</summary>'
            + "".join(parts) +
            f'<div style="font-size:12px;color:#6b6966;border-top:0.5px solid #e5e5f0;padding-top:.4rem">{escape(SAFETY)}</div></details>')


def render_for_fix(fix):
    return render(checks_for_fix(fix))


def render_for_rules(rule_ids):
    return render(checks_for_rules(rule_ids))
