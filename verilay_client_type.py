"""
verilay_client_type.py — a rough guess at WHAT KIND of client asked for a scan.

Verilay cannot know whether a person or an AI sent a request. This only reads the
"browser identity" each request announces (the User-Agent header) plus the Sec-Fetch-*
headers that real browsers add, and puts the request in one of a few plain buckets so
the owner can see, over time, whether scripts or AI tools already use the free scan.

Only the bucket's label is ever stored. Never the browser string, never an address.

Buckets:
  browser             looks like a normal browser and sent the headers real browsers send
  browser_unverified  claims to be a browser but did not send those headers: an older browser,
                      a privacy tool, or a script copying a browser's name
  script              a command-line tool, an HTTP library, or an automated/headless browser
  ai_agent            announces itself as an AI company's agent or crawler (GPTBot, ClaudeBot, ...)
  crawler             a search engine, link-preview or monitoring bot
  unknown             no browser identity at all, or one this list does not recognise

Honest limits: anything can lie about its identity, and an AI agent that drives a real browser
looks exactly like a person. Treat the numbers as a hint, not proof.
"""

AI_AGENTS = (
    "gptbot", "chatgpt-user", "chatgpt agent", "oai-searchbot", "openai", "claudebot", "claude-user", "claude-web",
    "claude-searchbot", "anthropic", "perplexitybot", "perplexity-user", "google-extended", "googleother",
    "gemini", "ccbot", "bytespider", "amazonbot", "meta-externalagent", "meta-externalfetcher",
    "applebot-extended", "cohere-ai", "mistralai-user", "youbot", "diffbot", "timpibot", "ai2bot", "firecrawl",
)

CRAWLERS = (
    "googlebot", "bingbot", "duckduckbot", "slurp", "baiduspider", "yandexbot", "applebot", "facebookexternalhit",
    "facebot", "twitterbot", "linkedinbot", "slackbot", "whatsapp", "telegrambot", "discordbot", "semrushbot",
    "ahrefsbot", "mj12bot", "petalbot", "uptimerobot", "pingdom", "statuscake",
)

SCRIPTS = (
    "curl/", "wget/", "python-requests", "python-urllib", "python-httpx", "httpx", "aiohttp", "go-http-client",
    "okhttp", "java/", "apache-httpclient", "node-fetch", "undici", "axios", "libwww-perl", "postmanruntime",
    "insomnia", "httpie", "powershell", "scrapy", "guzzle", "reqwest", "deno/", "bun/",
    "headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium",
)

_BROWSER_HINTS = ("mozilla/", "applewebkit", "gecko/", "chrome/", "safari/", "firefox/", "edg/", "opr/")

LABELS = {
    "browser": "Browser",
    "browser_unverified": "Looks like a browser, unverified",
    "script": "Script or tool",
    "ai_agent": "AI agent",
    "crawler": "Crawler or link preview",
    "unknown": "Unknown",
}


def classify(headers) -> str:
    """One of the bucket names above. Never raises."""
    try:
        ua = str(headers.get("User-Agent", "") or "")[:300].lower().strip()
        if not ua:
            return "unknown"
        if any(k in ua for k in AI_AGENTS):
            return "ai_agent"
        if any(k in ua for k in CRAWLERS):
            return "crawler"
        if any(k in ua for k in SCRIPTS):
            return "script"
        if any(k in ua for k in _BROWSER_HINTS):
            has_fetch_headers = bool(headers.get("Sec-Fetch-Site") or headers.get("Sec-Fetch-Mode"))
            return "browser" if has_fetch_headers else "browser_unverified"
        if any(w in ua for w in ("bot", "crawler", "spider")):
            return "crawler"
        return "unknown"
    except Exception:
        return "unknown"
