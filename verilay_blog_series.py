"""Blog series (3 Nov 2026). Moses asked how readers find every post in a series in one place. This module adds:
the "Follow a series" cards at the top of /blog, a box at the top of each series post listing every part, and
previous/next links at the bottom. Posts that aren't in a series don't change.

A part counts as published when its slug is in BLOG_POSTS. Until then it shows as "coming <date>" (or just as
planned if it has no date yet). So publishing a part means adding the post with that slug, and nothing here
needs to change. Keep the dates in step with Moses_ClaudeWorkspace\\verilay\\blog-calendar.md.
"""
import html as _html

SERIES = [
    {
        "key": "engineer",
        "name": "Building AI Apps Like an Engineer",
        "tag": "Learn the process",
        "blurb": "How engineers build apps, and whether AI builders do the same.",
        "bg": "#E1F5EE", "fg": "#085041", "accent": "#0F6E56",
        "parts": [
            ("building-ai-apps-like-an-engineer", "Introduction: I'm learning the path", ""),
            ("building-ai-apps-like-an-engineer-start-here", "Start here", ""),
            ("plain-english-glossary-for-ai-app-builders", "A plain-English glossary", "18 Nov"),
            ("ai-builder-rules-file", "The rules file", "2 Dec"),
            ("why-ai-builders-leave-the-database-open", "The open database", "16 Dec"),
            ("it-works-vs-its-done", "“It works” vs “it’s done”", ""),
            ("who-checks-what-ai-built-apps", "Who checks what", ""),
            ("when-a-human-engineer-is-worth-it", "When a human engineer is worth it", ""),
            ("choosing-an-ai-app-builder", "Choosing an AI app builder", ""),
            ("day-30-after-your-ai-app-launches", "Day 30: after your app goes live", ""),
        ],
    },
    {
        "key": "fix",
        "name": "Fix It With AI",
        "tag": "Fix problems safely",
        "blurb": "Fixing what a scan found, with AI, without breaking things.",
        "bg": "#FAECE7", "fg": "#712B13", "accent": "#993C1D",
        "parts": [
            ("you-can-fix-it-with-ai", "You built it with AI. You can fix it with AI too.", ""),
            ("fix-it-with-ai-understand-before-you-fix", "Understand before you fix", "11 Nov"),
            ("fix-it-with-ai-one-fix-at-a-time", "One fix at a time, with an undo point", "25 Nov"),
            ("fix-it-with-ai-how-do-you-know-it-worked", "How do you know it worked?", "9 Dec"),
            ("fix-it-with-ai-when-to-ask-a-human", "When to stop and ask a human", "6 Jan"),
        ],
    },
]

_e = lambda s: _html.escape(s, quote=True)


def _live(posts):
    return {p["slug"] for p in posts if p.get("body")}


def series_for(slug):
    """(series, index) for a post, or (None, -1) when it isn't part of a series."""
    for s in SERIES:
        for i, part in enumerate(s["parts"]):
            if part[0] == slug:
                return s, i
    return None, -1


def _coming(date):
    return "coming " + date if date else "planned"


def cards_html(posts):
    """'Follow a series' cards for the top of /blog. Empty when no series has a published part."""
    live = _live(posts)
    cards = []
    for s in SERIES:
        out = [p for p in s["parts"] if p[0] in live]
        if not out:
            continue
        nxt = next((p for p in s["parts"] if p[0] not in live), None)
        when = (" &middot; next: " + _e(nxt[2])) if nxt and nxt[2] else ""
        cards.append(
            '<div class="series-card">'
            '<span style="font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;background:' + s["bg"] + ';color:' + s["fg"] + '">' + _e(s["tag"]) + '</span>'
            '<div style="font-size:16px;font-weight:700;margin:.6rem 0 .3rem;line-height:1.3">' + _e(s["name"]) + '</div>'
            '<div style="font-size:13px;color:#6b6966;line-height:1.5;margin-bottom:.6rem">' + _e(s["blurb"]) + '</div>'
            '<div style="font-size:12px;color:#9a9893;margin-bottom:.8rem">' + str(len(out)) + ' of ' + str(len(s["parts"])) + ' parts out' + when + '</div>'
            '<a href="/blog/' + s["parts"][0][0] + '" style="font-size:13px;font-weight:600;color:' + s["accent"] + ';text-decoration:none">Start with part 1 &rarr;</a>'
            '</div>')
    if not cards:
        return ""
    return ('<style>.series-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-bottom:1.75rem}'
            '.series-card{background:#fff;border:0.5px solid #e8e6e0;border-radius:12px;padding:1rem 1.15rem}</style>'
            '<div style="font-size:12px;font-weight:600;color:#6b6966;letter-spacing:.06em;text-transform:uppercase;margin-bottom:.75rem">Follow a series</div>'
            '<div class="series-grid">' + "".join(cards) + '</div>')


def box_html(slug, posts):
    """Box for the top of a series post: which part this is, and every part (links when published)."""
    s, idx = series_for(slug)
    if not s:
        return ""
    live = _live(posts)
    rows, hidden = [], 0
    for i, (pslug, title, date) in enumerate(s["parts"]):
        if i == idx:
            rows.append('<li style="font-weight:600;color:#1a1917">' + str(i + 1) + '. ' + _e(title)
                        + ' <span style="font-weight:400;font-size:12px;color:#9a9893">&middot; you are here</span></li>')
        elif pslug in live:
            rows.append('<li><span style="color:' + s["accent"] + '">&#10003;</span> <a href="/blog/' + pslug + '" style="color:' + s["accent"] + '">'
                        + str(i + 1) + '. ' + _e(title) + '</a></li>')
        elif date:
            rows.append('<li style="color:#9a9893">' + str(i + 1) + '. ' + _e(title) + ' &middot; ' + _coming(date) + '</li>')
        else:
            hidden += 1
    if hidden:
        rows.append('<li style="color:#9a9893">' + str(hidden) + ' more planned</li>')
    return ('<details class="series-box" open style="border:0.5px solid #e8e6e0;border-radius:12px;padding:.9rem 1.15rem;margin:1.25rem 0;background:#fff">'
            '<summary style="cursor:pointer;font-size:13px;color:' + s["accent"] + ';font-weight:600">Part ' + str(idx + 1) + ' of ' + str(len(s["parts"]))
            + ' &middot; ' + _e(s["name"]) + '</summary>'
            '<ul style="list-style:none;padding:0;margin:.6rem 0 0;font-size:14px;line-height:1.9">' + "".join(rows) + '</ul></details>'
            '<script>(function(){var d=document.querySelectorAll(".series-box");'
            'if(window.matchMedia&&window.matchMedia("(max-width:600px)").matches){d.forEach(function(x){x.removeAttribute("open");});}})();</script>')


def nav_html(slug, posts):
    """Previous / next part links for the bottom of a series post."""
    s, idx = series_for(slug)
    if not s:
        return ""
    live = _live(posts)
    cell = 'display:block;border:0.5px solid #e8e6e0;border-radius:12px;padding:.85rem 1.1rem;text-decoration:none;color:#1a1917;background:#fff'
    left = right = "<div></div>"
    if idx > 0:
        pslug, title, _ = s["parts"][idx - 1]
        inner = '<div style="font-size:12px;color:#9a9893">&larr; Previous part</div><div style="font-weight:600;font-size:14px;margin-top:2px">' + _e(title) + '</div>'
        left = ('<a href="/blog/' + pslug + '" style="' + cell + '">' + inner + '</a>') if pslug in live else ('<div style="' + cell + '">' + inner + '</div>')
    if idx + 1 < len(s["parts"]):
        pslug, title, date = s["parts"][idx + 1]
        if pslug in live:
            right = ('<a href="/blog/' + pslug + '" style="' + cell + ';text-align:right"><div style="font-size:12px;color:#9a9893">Next part &rarr;</div>'
                     '<div style="font-weight:600;font-size:14px;margin-top:2px">' + _e(title) + '</div></a>')
        else:
            right = ('<div style="' + cell + ';text-align:right"><div style="font-size:12px;color:#9a9893">Next part &rarr;</div>'
                     '<div style="font-weight:600;font-size:14px;margin-top:2px">' + _e(title) + '</div>'
                     '<div style="font-size:12px;color:#9a9893;margin-top:2px">' + ("C" + _coming(date)[1:]) + '</div></div>')
    return ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:2rem 0">'
            + left + right + '</div>')
