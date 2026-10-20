"""verilay_checklist.py - the free 10-point checklist page and the blog post that goes with it (2026-10-20).

One list, written once, used by both the /checklist page and the blog post, so they cannot drift apart. Each item says why it
matters, a way to check it, and, honestly, how much Verilay itself covers it:

  "fixed"   a fixed rule that gives the same answer every time
  "ai"      the AI review reads the code it is given; it can vary and can miss things
  "you"     a test the reader runs themselves (the "Check it yourself" tests)
  "none"    not checked by Verilay at all

Rules it follows (decided with Moses, 2026-10-20):
  * It is general good practice. Never "a standard", never "a guarantee", never "what Verilay checks".
  * The coverage labels are checked against the code. If a scan rule changes, change the labels here and the test.
  * No other tool or company is named, and nothing refers to where the idea came from.
  * All wording is fixed text; nothing from a visitor or a report ever reaches this page.
"""
from html import escape

TITLE = "A 10-Point Security Checklist for AI-Built Apps"
SLUG = "10-point-security-checklist-ai-built-app"
DESCRIPTION = ("Ten plain-English questions to ask before real users or payments arrive: login, data, secrets, inputs, uploads, "
               "connections and packages. Free, general good practice, with what a scan can and can't tell you.")
NOT_A_STANDARD = "General good practice. Not a standard, and not a guarantee."

# coverage kind -> (chip text, chip colours)
KINDS = {
    "fixed": ("Verilay: fixed check", "#E1F5EE", "#085041"),
    "fixed_ai": ("Verilay: fixed check for some apps, plus AI review", "#E1F5EE", "#085041"),
    "ai": ("Verilay: AI review", "#EEEDFE", "#3C3489"),
    "you": ("Verilay: you test this one", "#FEF3C7", "#92400E"),
    "none": ("Verilay: not checked", "#F1EFE8", "#5F5E5A"),
}

ITEMS = [
    {"id": "login", "q": "Is the login checked on the server, including for admin pages, and not just hidden in the buttons?",
     "why": "Hiding a button doesn't protect a page. Anyone can type the address of an admin page or call the data directly, so the server itself has to say no.",
     "how": "Open a private (incognito) window, so you're not logged in, and paste the address of a page that should need a login. You should be sent to a login page. Then ask your AI builder: \"Show me where the server checks that the user is logged in for the admin pages.\"",
     "kind": "fixed_ai", "cover": "The AI review reads your login code. For Supabase apps, a fixed rule also looks for backend functions that skip the login check."},
    {"id": "two_accounts", "q": "Can one user see another user's data? Test with two accounts.",
     "why": "This is the most common serious mistake in apps with logins: the page works, but any logged-in user can see everyone's records.",
     "how": "Make two test accounts with two email addresses you own, A and B. As A, create something private. Log in as B in a different browser and try to find A's item, including by pasting A's page address.",
     "kind": "fixed_ai", "cover": "For Supabase apps, fixed rules look for missing access rules. The AI review looks at other apps. The two-account test is one only you can run."},
    {"id": "tables", "q": "Is access control on for every database table with user data?",
     "why": "A table with no access rule can be read, or changed, by anyone who has your app's public key, and that key is meant to be public.",
     "how": "Ask your AI builder to list every table that holds user data and the access rule on each. If you use Supabase, open each table in the dashboard and look for Row Level Security switched on.",
     "kind": "fixed_ai", "cover": "A fixed rule checks Supabase apps. For other databases the AI review looks, and can miss things."},
    {"id": "secrets", "q": "Any keys or passwords in the code or its history? Are secrets kept on the server only?",
     "why": "Bots scan public code for keys within minutes. Deleting a file doesn't remove a key from the project's history, so a leaked key has to be replaced, not just hidden.",
     "how": "Open your live app, view the page source (Ctrl+U) and search for words like secret, key and token. Search your code the same way. If a real key appears anywhere, make a new key in the service's own dashboard and switch to it.",
     "kind": "fixed", "cover": "A fixed check reads every current file for keys and passwords. It does not read a project's history."},
    {"id": "inputs", "q": "Does the app treat typed text as data, not code?",
     "why": "If an app puts what you type straight into a database query or onto a page, a clever input can read data or run code. These are called injection and cross-site scripting.",
     "how": "In a search box or a form, type a single apostrophe and submit. Then type <b>test</b> into a box whose content is shown back later. You should see the characters exactly as typed, and a normal error at worst.",
     "kind": "ai", "cover": "The AI review looks for it in the code. You can also run the two tests above. A clean result doesn't prove an app is safe."},
    {"id": "uploads", "q": "Are uploads limited by type and size?",
     "why": "An upload box that accepts anything can be used to store harmful files or to fill up your storage and your bill.",
     "how": "Try uploading a harmless file of the wrong kind, such as a text file where only pictures are expected. The app should refuse it with a clear message.",
     "kind": "ai", "cover": "The AI review looks at upload code. Whether an uploaded file could be dangerous needs an experienced person."},
    {"id": "cors", "q": "Does CORS allow only your own site?",
     "why": "CORS decides which other websites may talk to your app's server from a visitor's browser. If it allows every site, any website can ask your server for data on a visitor's behalf.",
     "how": "Ask your AI builder: \"What origins does our CORS setting allow, and is it set to everything?\" For anything that returns private data, the answer should be your own site, not a star.",
     "kind": "ai", "cover": "The AI review may notice it. It isn't a fixed rule, so don't rely on a scan for this one."},
    {"id": "limits", "q": "Are there limits on login attempts and costly actions?",
     "why": "Without limits, someone can try thousands of passwords, or call an AI feature in a loop and run up your bill.",
     "how": "On a test account, enter a wrong password about ten times in a row. You should be slowed down or blocked. Ask your AI builder what limits exist on anything that costs you money.",
     "kind": "ai", "cover": "The AI review looks for it. The wrong-password test is one you run yourself."},
    {"id": "webhooks", "q": "Do payment and webhook endpoints check who is calling?",
     "why": "A webhook is a message from another service, such as \"this payment succeeded\". If your app believes any message without checking the sender, someone can fake a payment.",
     "how": "Ask your AI builder: \"Does our payment webhook verify the signature from the payment provider before it trusts the message?\"",
     "kind": "ai", "cover": "The AI review looks at these endpoints. A person should confirm anything that touches money."},
    {"id": "packages", "q": "Are packages updated, with the lock file saved?",
     "why": "Apps are built from other people's packages, and old versions can have known holes. A saved lock file lists exactly which versions you use, so they can be checked.",
     "how": "On GitHub, open your repository, then Security, then Dependabot alerts. Update packages one at a time and test after each.",
     "kind": "fixed", "cover": "A fixed check compares your packages with OSV.dev, a public list of known vulnerabilities. Updating them is up to you."},
]

EXTRA = {"title": "Also worth having: backups and a way to roll back",
         "why": "If an update breaks something, or data is deleted by mistake, you want a copy and a way to go back to the last version that worked.",
         "how": "A GitHub repository keeps every earlier version of your code. For your data, switch on your database's backups and find out how to restore one.",
         "kind": "none", "cover": "This lives outside the code, so a scan can't see it."}

HOW_IT_FITS = ("Verilay covers parts of this list: fixed checks for keys in your code, known-vulnerable packages and, for Supabase apps, "
               "access rules, plus an AI review of the code it reads. The AI review can vary and can miss things, and the free scan reads the "
               "most important files rather than all of them. Everything else you test yourself, or ask a person to look at.")
FREE_FIRST = ("If you're not sure yet that your app will earn anything, the free version is a good place to start: fix what it finds with "
              "your AI builder first, and think about a deeper review once you have users or payments to protect.")
PERSON = "For anything serious, such as real money or sensitive data, have an experienced person look as well."


def _t(s):
    """Escape, then use a curly apostrophe like the rest of the site."""
    return escape(str(s), quote=False).replace("'", "&rsquo;")


def _chip(kind):
    text, bg, fg = KINDS[kind]
    return (f'<span style="display:inline-block;background:{bg};color:{fg};font-size:11.5px;font-weight:600;padding:2px 9px;'
            f'border-radius:20px">{_t(text)}</span>')


def _item_block(n, it):
    num = f"{n}. " if n else ""
    q = it["q"] if "q" in it else it["title"]
    return (f'<div class="ck" id="{escape(it.get("id", "extra"))}">'
            f'<h2>{num}{_t(q)}</h2>'
            f'<p><strong>Why it matters.</strong> {_t(it["why"])}</p>'
            f'<p><strong>How to check.</strong> {_t(it["how"])}</p>'
            f'<p style="margin-bottom:0">{_chip(it["kind"])} <span style="font-size:13px;color:#6b6966">{_t(it["cover"])}</span></p></div>')


_CSS = """:root{--ease-out:cubic-bezier(.23,1,.32,1);--dur-base:180ms;--dur-fast:120ms}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8f8f7;color:#1a1917;min-height:100vh;font-size:15px;-webkit-font-smoothing:antialiased}
.wrap{max-width:680px;margin:0 auto;padding:2rem 1.5rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:#fff;border-bottom:0.5px solid #e8e6e0;margin-bottom:2.5rem}
h2{font-size:17px;font-weight:600;margin:0 0 .5rem}
p{color:#4a4846;line-height:1.65;margin-bottom:.75rem;font-size:14px}
.ck{background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem 1.15rem;margin-bottom:.85rem}
.box{background:#EEEDFE;border-radius:12px;padding:1rem 1.15rem;margin:1.25rem 0}
a{color:#534AB7;transition:opacity var(--dur-base) ease}
@media (hover: hover) and (pointer: fine){a:hover{opacity:.75}}
.cta-btn{display:inline-block;font-size:13px;padding:8px 20px;background:#534AB7;color:#fff!important;border-radius:20px;text-decoration:none;transition:transform var(--dur-fast) var(--ease-out),opacity var(--dur-base) ease}
.cta-btn:active{transform:translateY(0) scale(.97)}
a:focus-visible,button:focus-visible{outline:2px solid #534AB7;outline-offset:2px}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}
@media(max-width:600px){.wrap{padding:1rem}}"""

_LOGO = ('<svg width="24" height="24" viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;vertical-align:middle">'
         '<rect width="400" height="400" rx="88" fill="#534AB7"/><circle cx="200" cy="200" r="112" fill="#ffffff" fill-opacity="0.12"/>'
         '<path d="M140 142 L200 268 L260 142" fill="none" stroke="#ffffff" stroke-width="28" stroke-linecap="round" stroke-linejoin="round"/>'
         '<path d="M122 142 L278 142" fill="none" stroke="#ffffff" stroke-width="28" stroke-linecap="round"/></svg>')


def render_page():
    """The full /checklist page as HTML."""
    items = "".join(_item_block(i, it) for i, it in enumerate(ITEMS, 1))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_t(TITLE)} | Verilay</title>
<meta name="description" content="{escape(DESCRIPTION)}">
<link rel="canonical" href="https://verilay.dev/checklist">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Verilay">
<meta property="og:title" content="{_t(TITLE)}">
<meta property="og:description" content="{escape(DESCRIPTION)}">
<meta property="og:url" content="https://verilay.dev/checklist">
<style>{_CSS}</style>
</head>
<body>
<nav>
  <a href="/" style="font-weight:700;font-size:17px;text-decoration:none;color:#1a1917">{_LOGO} <span style="vertical-align:middle">Verilay</span></a>
  <a href="/" style="font-size:13px;color:#6b6966;text-decoration:none">Back to app</a>
</nav>
<div class="wrap">
  <div style="margin-bottom:1.5rem">
    <div style="font-size:12px;font-weight:600;color:#534AB7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem">Free checklist</div>
    <h1 style="font-size:26px;font-weight:700;margin-bottom:.5rem">{_t(TITLE)}</h1>
    <p>AI builders are good at making an app work. They are less good at telling you what is still left open. These are ten plain questions to ask before real users or payments arrive. You don't need to read code to ask them: for each one there is a way to check it yourself, or a question to put to your AI builder.</p>
    <p style="font-size:13px;color:#6b6966">{_t(NOT_A_STANDARD)} Each item also says how much Verilay itself covers it, and where the answer is that it doesn't.</p>
  </div>
  {items}
  {_item_block(None, EXTRA)}
  <div class="box"><p style="margin-bottom:.5rem"><strong>Where Verilay fits.</strong> {_t(HOW_IT_FITS)}</p>
    <p style="margin-bottom:.5rem">{_t(FREE_FIRST)}</p>
    <p style="margin-bottom:.75rem">{_t(PERSON)}</p>
    <a class="cta-btn" href="/">Run a free check</a>
    <span style="font-size:12.5px;color:#6b6966;margin-left:8px">No account needed. Public GitHub link or a ZIP. <a href="/privacy">What we keep</a></span></div>
  <p style="font-size:12.5px;color:#6b6966">Written by Moses, a non-developer who builds with AI tools. If something here is unclear or wrong, email <a href="mailto:moses@verilay.dev">moses@verilay.dev</a>.</p>
</div>
</body>
</html>"""


def render_blog_body():
    """The blog post's body (inside the post template): short, first person, linking to the full page."""
    one_liners = "".join(f"<li>{_t(it['q'])}</li>" for it in ITEMS)
    fixed = [i + 1 for i, it in enumerate(ITEMS) if it["kind"] in ("fixed", "fixed_ai")]
    return (
        "<p>I'm not a developer. I build apps with AI tools, and for a long time my plan for security was to hope the AI had handled it. "
        "What I wanted was a short list of plain questions I could actually ask, and a way to check the answers without reading code.</p>"
        "<p>So I wrote one. It's ten questions, and it's the list I now run through before real users or payments arrive.</p>"
        "<h2>The ten questions</h2>"
        f"<ol>{one_liners}</ol>"
        "<p>For each one, the <a href=\"/checklist\">full checklist</a> gives a plain reason it matters, a way to check it yourself or a question to put to your AI builder, "
        "and an honest note on whether Verilay covers it.</p>"
        "<h2>Why questions, not a scan result</h2>"
        "<p>A scan result is a lead, not a verdict. It can tell you something looks wrong, but it can't know your app the way your AI builder does, "
        "and it can't see settings that live in a dashboard. A question you can test yourself is harder to misunderstand. "
        "Open a private window and try to reach a page that should need a login. Make two test accounts and see whether one can see the other's data. "
        "Type a single apostrophe into a search box. Each takes a couple of minutes, and none of them needs you to read code.</p>"
        "<h2>What Verilay covers, and what it doesn't</h2>"
        f"<p>{_t(HOW_IT_FITS)}</p>"
        f"<p>Of the ten, fixed checks cover items {', '.join(str(n) for n in fixed[:-1])} and {fixed[-1]} in part or in full. "
        "The AI review looks at most of the rest, and it can miss things. Backups and rolling back live outside the code, so a scan can't see them at all. "
        "That's why the checklist says plainly which is which.</p>"
        "<h2>If you're not sure your app will earn anything</h2>"
        f"<p>{_t(FREE_FIRST)}</p>"
        f"<p>{_t(PERSON)}</p>"
        "<h2>Try it</h2>"
        "<p>The <a href=\"/checklist\">checklist</a> is free to read, with no sign-up. If you'd like a first look at your own app, "
        "paste a public GitHub link or upload a ZIP at <a href=\"/\">verilay.dev</a>. It usually takes one to three minutes. "
        "If anything on the list is unclear, or you think something is missing, tell me and I'll improve it.</p>"
        f"<p style=\"font-size:13px;color:#6b6966\">{_t(NOT_A_STANDARD)}</p>")
