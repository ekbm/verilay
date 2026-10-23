"""verilay_sitecheck.py - "Site setup": what a live address shows about how the site is set up, and how to fix it (23 Oct 2026).

A live-address scan used to say "give me a GitHub link for the real review" and leave the visitor with little to act on. These are things
that can be read from outside, in the way a browser reads them, that the owner can usually fix in a few minutes:

  * which browser-protection headers are missing (read by verilay_livecheck.py; this module writes the fix)
  * whether plain http:// is sent on to https://
  * how many days are left on the certificate
  * whether the cookies the page sets are protected (Secure, HttpOnly, SameSite)
  * whether the headers give away what software and version the server runs
  * for a domain the owner controls: SPF and DMARC email records (so nobody can send mail pretending to be them)
  * whether there is a /.well-known/security.txt (where a researcher should report a problem)

Rules it follows (same as verilay_livecheck.py):
  * PASSIVE ONLY. One normal page request, one request to the http:// address, one certificate handshake, public DNS lookups, and the
    standard security.txt path. It never probes paths such as /.env or /.git, and never tries to log in or break anything. Those would be
    uninvited attacks on a site the visitor may not own.
  * Only FACTS are stored in the report (names of cookies and their flags, a header name and value, yes/no results). All wording, steps
    and paste-in prompts are fixed text kept here, written by hand for each hosting platform.
  * No grade. The result is a checklist of "fine" and "worth fixing". A fact that cannot be read is left out, never guessed.
  * Never raises. Every value is escaped when drawn.
"""
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlparse

import verilay_url_guard as guard

BUDGET_SECONDS = 12
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DOH = "https://cloudflare-dns.com/dns-query"
CERT_WARN_DAYS = 14

# The values suggested for each protection header. The Content-Security-Policy is deliberately the safe part only (no framing, no <base>
# tricks, no plugins): a policy that limits scripts can break a working site, so that stays a separate, careful job.
HEADER_VALUES = {
    "Strict-Transport-Security": "max-age=15552000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
}

# Addresses on these belong to the platform: the owner cannot change their email records or certificate.
PLATFORM_DOMAINS = (
    ("lovable.app", "lovable"), ("lovable.dev", "lovable"), ("lovableproject.com", "lovable"),
    ("replit.app", "replit"), ("repl.co", "replit"), ("replit.dev", "replit"),
    ("vercel.app", "vercel"), ("netlify.app", "netlify"), ("pages.dev", "cloudflare"),
    ("up.railway.app", "railway"), ("railway.app", "railway"), ("onrender.com", "render"),
    ("github.io", "github-pages"), ("web.app", "firebase"), ("firebaseapp.com", "firebase"),
    ("herokuapp.com", "heroku"), ("fly.dev", "fly"), ("glitch.me", "glitch"), ("bolt.host", "bolt"),
    ("webflow.io", "webflow"), ("surge.sh", "surge"), ("supabase.co", "supabase"),
)
PLATFORM_LABELS = {
    "lovable": "Lovable", "replit": "Replit", "vercel": "Vercel", "netlify": "Netlify", "cloudflare": "Cloudflare", "railway": "Railway",
    "render": "Render", "github-pages": "GitHub Pages", "firebase": "Firebase", "heroku": "Heroku", "fly": "Fly.io", "glitch": "Glitch",
    "bolt": "Bolt", "webflow": "Webflow", "surge": "Surge", "supabase": "Supabase", "express": "an Express (Node) server",
    "flask": "a Flask (Python) server", "nginx": "an nginx server", "apache": "an Apache server", "unknown": "your host",
}
_MULTI_TLD = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "co.in", "co.jp", "com.sg", "com.mx", "com.ar", "com.tr"}
_SESSION_NAME = re.compile(r"(sess|sid\b|token|auth|jwt|login|connect\.sid|__session|csrf|remember)", re.I)


# ── reading a site ───────────────────────────────────────────────────────────

def _apex(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _domain_kind(host):
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host or ""):
        return "unknown"
    for suffix, _p in PLATFORM_DOMAINS:
        if host == suffix or host.endswith("." + suffix):
            return "platform"
    return "own"


def _platform(host, headers):
    """Which kind of host or server this looks like, from the address and the headers. 'unknown' when it cannot tell."""
    for suffix, key in PLATFORM_DOMAINS:
        if host == suffix or host.endswith("." + suffix):
            return key
    h = {str(k).lower(): str(v).lower() for k, v in dict(headers or {}).items()}
    if "x-vercel-id" in h or h.get("server") == "vercel":
        return "vercel"
    if "x-nf-request-id" in h or h.get("server") == "netlify":
        return "netlify"
    if "express" in h.get("x-powered-by", ""):
        return "express"
    srv = h.get("server", "")
    if "gunicorn" in srv or "werkzeug" in srv:
        return "flask"
    if "nginx" in srv:
        return "nginx"
    if "apache" in srv:
        return "apache"
    if "cloudflare" in srv or "cf-ray" in h:
        return "cloudflare"
    return "unknown"


def _cookie_flags(raw_list):
    """[{name, secure, httponly, samesite}] from Set-Cookie lines. Names and flags only: a value is never kept."""
    out = []
    for raw in raw_list or []:
        parts = [p.strip() for p in str(raw).split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()[:60]
        attrs = [p.lower() for p in parts[1:]]
        ss = next((a.split("=", 1)[1].strip() for a in attrs if a.startswith("samesite=")), None)
        out.append({"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs, "samesite": ss})
    return out[:12]


def _set_cookies(resp):
    try:
        got = resp.raw.headers.getlist("Set-Cookie")
        if got:
            return list(got)
    except Exception:
        pass
    one = (getattr(resp, "headers", None) or {}).get("Set-Cookie")
    return [one] if one else []


def _leaks(headers):
    """Headers that name the server software, with a version where it adds information. [{header, value}]"""
    h = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
    out = []
    if h.get("x-powered-by"):
        out.append({"header": "X-Powered-By", "value": h["x-powered-by"][:60]})
    if h.get("server") and re.search(r"\d+\.\d+", h["server"]):
        out.append({"header": "Server", "value": h["server"][:60]})
    for name, shown in (("x-aspnet-version", "X-AspNet-Version"), ("x-aspnetmvc-version", "X-AspNetMvc-Version")):
        if h.get(name):
            out.append({"header": shown, "value": h[name][:40]})
    return out


def _plain_get(url):
    import requests
    return requests.get(url, allow_redirects=False, timeout=8, headers={"User-Agent": UA})


def _cert_days(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def _dns(name, rtype):
    """Answers for one public DNS name through Cloudflare's public resolver: a list of strings ([] = no such record), or None if the
    lookup itself failed. Only the domain the visitor typed is looked up."""
    import requests
    r = requests.get(DOH, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"}, timeout=6)
    d = r.json()
    if d.get("Status") not in (0, 3):
        return None
    return [str(a.get("data", "")).strip('"').replace('" "', "") for a in (d.get("Answer") or []) if isinstance(a, dict)]


def _email_facts(domain, dns):
    clean = lambda rows: None if rows is None else [str(t).strip().strip('"') for t in rows]
    txt = clean(dns(domain, "TXT"))
    mx = dns(domain, "MX")
    dm = clean(dns("_dmarc." + domain, "TXT"))
    if txt is None and dm is None:
        return None
    spf = None if txt is None else any(t.lower().startswith("v=spf1") for t in txt)
    policy = None
    if dm is not None:
        rec = next((t for t in dm if t.lower().startswith("v=dmarc1")), None)
        m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", rec or "", re.I)
        policy = m.group(1).lower() if m else ("none" if rec else "absent")
        policy = "absent" if rec is None else policy
    return {"domain": domain, "spf": spf, "dmarc": policy, "has_mx": (None if mx is None else bool(mx))}


def collect(url, get=None, get_plain=None, cert_days=None, dns=None, budget=BUDGET_SECONDS):
    """Facts about a live address. Small and safe to store ({} when the page cannot be read). Never raises. The network steps can be replaced (tests)."""
    try:
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            return {}
        p = urlparse(url)
        host = (p.hostname or "").lower()
        https = p.scheme.lower() == "https"
        guard.validate_url(url)                                  # refuses private and internal addresses
        main = (get or guard.safe_get)(url, timeout=10, headers={"User-Agent": UA})
        facts = {"host": host, "https": https, "domain_kind": _domain_kind(host), "platform": _platform(host, main.headers),
                 "cookies": _cookie_flags(_set_cookies(main)), "leaks": _leaks(main.headers),
                 "https_redirect": None, "cert_days": None, "security_txt": None, "email": None}
    except Exception:
        return {}

    def redirect():
        try:
            plain = "http://" + url.split("://", 1)[1]
            guard.validate_url(plain)
            r = (get_plain or _plain_get)(plain)
            loc = str((getattr(r, "headers", None) or {}).get("Location", ""))
            return bool(r.status_code in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"))
        except Exception:
            return None

    def cert():
        try:
            return (cert_days or _cert_days)(host)
        except Exception:
            return None

    def sectxt():
        try:
            r = (get or guard.safe_get)(f"{p.scheme}://{p.netloc}/.well-known/security.txt", timeout=8, headers={"User-Agent": UA})
            ctype = str((getattr(r, "headers", None) or {}).get("Content-Type", "")).lower()
            body = getattr(r, "text", "") or ""
            return bool(r.status_code == 200 and "text/plain" in ctype and re.search(r"^\s*contact\s*:", body, re.I | re.M))
        except Exception:
            return None

    def email():
        if facts["domain_kind"] != "own":
            return None
        try:
            return _email_facts(_apex(host.removeprefix("www.")), dns or _dns)
        except Exception:
            return None

    jobs = {"https_redirect": redirect, "cert_days": cert if https else (lambda: None), "security_txt": sectxt, "email": email}
    pool = ThreadPoolExecutor(max_workers=4)
    try:
        futs = {k: pool.submit(fn) for k, fn in jobs.items()}
        wait(list(futs.values()), timeout=budget)
        for k, f in futs.items():
            if f.done():
                try:
                    facts[k] = f.result()
                except Exception:
                    pass
    finally:
        pool.shutdown(wait=False)
    return facts


# ── fixed wording: why it matters and how to fix it, written by hand ─────────

def _lines(missing):
    return "\n".join(f"{h}: {HEADER_VALUES[h]}" for h in missing)


def _fix_headers(platform, missing):
    """Steps, an optional code block and a paste-in prompt for adding the missing headers on this kind of host."""
    block = _lines(missing)
    names = ", ".join(missing)
    prompt = ("Add these HTTP security headers to every response my app sends, and change nothing else:\n" + block +
              "\nIf my hosting platform does not let app code set headers, tell me exactly where in its settings to add them, or whether I should "
              "put Cloudflare (free) in front of my domain. Then tell me how to check that the headers arrive.")
    if platform == "express":
        code = ('import helmet from "helmet";\napp.disable("x-powered-by");\napp.use(helmet({\n'
                '  contentSecurityPolicy: { useDefaults: false, directives: { "frame-ancestors": ["\'none\'"], "base-uri": ["\'self\'"], "object-src": ["\'none\'"] } },\n'
                '  frameguard: { action: "deny" },\n  referrerPolicy: { policy: "strict-origin-when-cross-origin" },\n  hsts: { maxAge: 15552000 },\n}));\n'
                'app.use((req, res, next) => { res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"); next(); });')
        return (["Your server looks like Express. Run: npm install helmet", "Add the code shown below near the top of your server file, before your routes.",
                 "Redeploy, then scan this address again."], code,
                prompt + "\nThis is an Express app: use the helmet package, and keep its script policy off for now so the page does not break.")
    if platform == "flask":
        body = "\n".join(f'    resp.headers.setdefault("{h}", "{HEADER_VALUES[h]}")' for h in missing)
        code = f"@app.after_request\ndef add_security_headers(resp):\n{body}\n    return resp"
        return (["Your server looks like Flask. Add the code shown below to your app file.", "Redeploy, then scan this address again."], code, prompt)
    if platform == "vercel":
        items = ",\n".join(f'      {{ "key": "{h}", "value": "{HEADER_VALUES[h]}" }}' for h in missing)
        code = '{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n' + items + "\n      ]\n    }\n  ]\n}"
        return (["On Vercel, headers are set in a file called vercel.json at the top of your project.", "Add (or merge) the code shown below into it.",
                 "Redeploy, then scan this address again."], code, prompt)
    if platform == "netlify":
        code = "/*\n" + "\n".join(f"  {h}: {HEADER_VALUES[h]}" for h in missing)
        return (["On Netlify, headers are set in a file called _headers in the folder you publish.", "Create it with the content shown below.",
                 "Redeploy, then scan this address again."], code, prompt)
    if platform == "cloudflare":
        return (["In Cloudflare, open your domain, then Rules, then Transform Rules, then Modify Response Header, and create a rule that applies to all requests.",
                 "Add one \"Set static\" action for each header below (name on the left, value on the right).", "Save, then scan this address again."], block, prompt)
    if platform == "github-pages":
        return (["GitHub Pages does not let you add response headers.",
                 "The usual fix is to put your own domain behind Cloudflare (free) and add the headers there (Rules, Transform Rules, Modify Response Header).",
                 "Or move the site to Netlify or Vercel, which let you set them."], block, prompt)
    if platform in ("nginx",):
        code = "\n".join(f'add_header {h} "{HEADER_VALUES[h]}" always;' for h in missing)
        return (["Your server looks like nginx. Add the lines shown below inside the server block of your config, then reload nginx.", "Scan this address again."], code, prompt)
    if platform in ("lovable", "replit", "bolt", "unknown", "render", "railway", "heroku", "fly", "glitch", "firebase", "webflow", "surge", "supabase", "apache"):
        return ([f"Ask your AI builder to add them, using the prompt below. If it says your host does not allow it, put your own domain behind Cloudflare (free) "
                 "and add the headers there (Rules, Transform Rules, Modify Response Header).", "The headers to add are shown below.", "Scan this address again afterwards."], block, prompt)
    return (["Ask your AI builder to add them, using the prompt below.", "The headers to add are shown below."], block, prompt)


def _fix_redirect(platform):
    prompt = ("Make my app send every request that arrives over plain http:// on to the same address over https:// (a permanent redirect), "
              "and change nothing else. If I am behind a proxy, check the X-Forwarded-Proto header so it does not loop.")
    if platform == "cloudflare":
        return (["In Cloudflare, open your domain, then SSL/TLS, then Edge Certificates, and turn on \"Always Use HTTPS\"."], None, prompt)
    if platform in ("vercel", "netlify"):
        return (["This is normally on by itself on this host. Check the domain settings of your project and make sure your own domain shows a valid certificate."], None, prompt)
    return (["Look for a setting called \"Force HTTPS\" or \"Always use HTTPS\" in your host's domain settings, or use the prompt below."], None, prompt)


def _fix_cookies(platform, names):
    prompt = (f"My app sets these cookies without full protection: {', '.join(names)}. Find where each one is set and add Secure, HttpOnly and SameSite=Lax "
              "(only keep HttpOnly off for a cookie the page's own JavaScript really needs to read). Change nothing else.")
    if platform == "express":
        return (["In Express, set the flags where you create the cookie, as shown below."], 'res.cookie("session", value, { httpOnly: true, secure: true, sameSite: "lax" });', prompt)
    if platform == "flask":
        return (["In Flask, add the settings shown below to your config."], 'app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")', prompt)
    return (["Ask your AI builder to add the three flags to your login or session cookie, using the prompt below."], None, prompt)


def _fix_leaks(platform):
    prompt = "Stop my server from sending headers that name the software and its version (X-Powered-By, and a version number in Server). Change nothing else."
    if platform == "express":
        return (["Add the line shown below to your server file, then redeploy."], 'app.disable("x-powered-by");', prompt)
    if platform == "nginx":
        return (["In your nginx config add the line shown below inside the http block, then reload."], "server_tokens off;", prompt)
    if platform == "apache":
        return (["In your Apache config add the lines shown below, then reload."], "ServerTokens Prod\nServerSignature Off", prompt)
    return (["Ask your AI builder to turn these headers off, using the prompt below."], None, prompt)


SPF_STEPS = ["Open the DNS settings of your domain (at your registrar, or at Cloudflare if your domain is there).",
             "Add a TXT record on your domain itself. Its value starts with v=spf1, then \"include:\" and your email provider's name, then ~all.",
             "Examples: Google Workspace is v=spf1 include:_spf.google.com ~all, Microsoft 365 is v=spf1 include:spf.protection.outlook.com ~all, "
             "Zoho is v=spf1 include:one.zoho.com ~all. Your email provider's help page gives the exact line.",
             "If you already have an SPF record, add the include to it. A domain should have only one."]
DMARC_STEPS = ["Open the DNS settings of your domain and add a TXT record named _dmarc.",
               "Use this value, with your own address: v=DMARC1; p=none; rua=mailto:you@yourdomain.com",
               "p=none only watches at first: you receive daily summaries of who sends mail as your domain. After a few weeks, if all your mail shows as "
               "legitimate, change p=none to p=quarantine."]
SECTXT_CODE = "Contact: mailto:you@yourdomain.com\nExpires: 2027-12-31T00:00:00Z\nPreferred-Languages: en"
SECTXT_STEPS = ["Create a text file named security.txt and make it available at /.well-known/security.txt on your site.",
                "Put your own email address after Contact, and a date within the next year after Expires:",
                "On most hosts, put the file in a folder named .well-known inside your public (or static) folder."]
SECTXT_PROMPT = ("Serve a plain-text file at /.well-known/security.txt on my site with these lines (use my real contact email, and an Expires date less than a year ahead):\n"
                 + SECTXT_CODE + "\nChange nothing else.")


# ── turning facts into the wording the page shows ────────────────────────────

def _item(id_, status, title, why, detail=None, fix=None, priority=0):
    d = {"id": id_, "status": status, "title": title, "why": why, "detail": detail, "steps": [], "code": None, "prompt": None, "priority": priority}
    if fix and status == "check":
        d["steps"], d["code"], d["prompt"] = list(fix[0]), fix[1], fix[2]
    return d


def view(facts, live=None):
    """Plain data for the page and the browser script: facts joined to fixed wording. Never raises; {"has": False} when there is nothing to show."""
    try:
        if not isinstance(facts, dict) or not facts.get("host"):
            return {"has": False}
        plat = facts.get("platform") if facts.get("platform") in PLATFORM_LABELS else "unknown"
        items = []

        # the six headers: one fix for all that are missing
        header_fix = None
        if isinstance(live, dict) and isinstance(live.get("headers"), dict):
            missing = []
            for name in HEADER_VALUES:
                sent = bool(live["headers"].get(name))
                covered = name == "X-Frame-Options" and bool(live.get("frame_ancestors_in_csp"))
                if not sent and not covered:
                    missing.append(name)
            if missing:
                steps, code, prompt = _fix_headers(plat, missing)
                header_fix = {"missing": missing, "steps": steps, "code": code, "prompt": prompt,
                              "intro": "To add the " + str(len(missing)) + " missing header" + ("s" if len(missing) != 1 else "") + " (" + ", ".join(missing) + ")"}

        if facts.get("https") and facts.get("https_redirect") is not None:
            ok = facts["https_redirect"] is True
            items.append(_item("redirect", "ok" if ok else "check", "Plain http is sent on to https",
                               "If someone types the address without https, the site should move them to the secure version. Otherwise their first visit travels unprotected.",
                               "Yes, it does." if ok else "No: the plain http:// address does not send visitors on to https://.", _fix_redirect(plat), 2))
        days = facts.get("cert_days")
        if facts.get("https") and isinstance(days, int) and not isinstance(days, bool):
            soon = days <= CERT_WARN_DAYS
            items.append(_item("certificate", "check" if soon else "ok", "Certificate",
                               "The certificate is what makes the padlock work. When it expires, browsers show a frightening warning and visitors leave.",
                               (f"Expires in {days} day{'s' if days != 1 else ''}." if days >= 0 else "It has expired."),
                               (["Most hosts renew certificates by themselves. If the date keeps getting closer, open the domain or SSL settings of your host and look for \"renew\" or \"reissue\"."],
                                None, "My site's certificate expires soon. Tell me how to check that it renews automatically on my host, and how to renew it by hand if it does not.") if soon else None, 2))
        cookies = facts.get("cookies")
        if isinstance(cookies, list):
            weak = [c for c in cookies if isinstance(c, dict) and _SESSION_NAME.search(str(c.get("name", "")))
                    and (not c.get("httponly") or (facts.get("https") and not c.get("secure")) or not c.get("samesite"))]
            names = [str(c["name"]) for c in weak]
            if weak:
                miss = []
                for c in weak:
                    m = [w for w, bad in (("Secure", facts.get("https") and not c.get("secure")), ("HttpOnly", not c.get("httponly")), ("SameSite", not c.get("samesite"))) if bad]
                    miss.append(f"{c['name']} (no {', '.join(m)})")
                items.append(_item("cookies", "check", "Sign-in cookies are protected",
                                   "A cookie that keeps someone logged in should only travel over https (Secure), be hidden from page scripts (HttpOnly) and not be sent along with requests from other sites (SameSite).",
                                   "Missing protection on: " + "; ".join(miss) + ".", _fix_cookies(plat, names), 1))
            elif cookies:
                items.append(_item("cookies", "ok", "Sign-in cookies are protected", "A cookie that keeps someone logged in should be Secure, HttpOnly and SameSite.",
                                   "No sign-in or session cookie without protection was seen on the first page.", None, 1))
        leaks = facts.get("leaks")
        if isinstance(leaks, list):
            if leaks:
                items.append(_item("leaks", "check", "The server does not announce what it runs",
                                   "A header that names the software and its version tells an attacker which known weaknesses to try. It is easy to switch off.",
                                   "Sent: " + "; ".join(f"{l.get('header')}: {l.get('value')}" for l in leaks if isinstance(l, dict)) + ".", _fix_leaks(plat), 3))
            else:
                items.append(_item("leaks", "ok", "The server does not announce what it runs", "A header that names the software and its version helps an attacker.",
                                   "No software name or version was seen in the headers.", None, 3))
        em = facts.get("email")
        if isinstance(em, dict):
            has_mail = em.get("has_mx") is True or em.get("spf") is True
            dom = escape(str(em.get("domain", "")))
            if has_mail or em.get("has_mx") is None:
                if em.get("spf") is False:
                    items.append(_item("spf", "check", "Email: SPF record", "SPF lists who may send email as your domain. Without it, mail from you is more likely to land in spam, and easier to fake.",
                                       f"No SPF record was found for {em.get('domain')}.", (SPF_STEPS, None, "Help me add a correct SPF record to my domain's DNS for the email provider I use. Ask me which provider it is."), 4))
                elif em.get("spf") is True:
                    items.append(_item("spf", "ok", "Email: SPF record", "SPF lists who may send email as your domain.", f"Found for {em.get('domain')}.", None, 4))
                d = em.get("dmarc")
                if d == "absent":
                    items.append(_item("dmarc", "check", "Email: DMARC record", "DMARC tells receiving mail systems what to do with mail that pretends to come from your domain. Without it, anyone can send mail that looks like yours.",
                                       f"No DMARC record was found for {em.get('domain')}.", (DMARC_STEPS, None, "Help me add a DMARC record (starting with p=none and an rua address) to my domain's DNS, and explain when to move it to p=quarantine."), 4))
                elif d == "none":
                    items.append(_item("dmarc", "check", "Email: DMARC is only watching", "p=none means the record reports but does not act. That is the right first step, and a few weeks later it should move to p=quarantine.",
                                       f"DMARC for {em.get('domain')} is set to p=none.", (["Keep p=none for a few weeks and read the daily summaries sent to your rua address.", "When all your real mail shows as legitimate, change p=none to p=quarantine in the same DNS record."], None,
                                                                                        "Explain how to read my DMARC reports and when it is safe to change p=none to p=quarantine."), 5))
                elif d in ("quarantine", "reject"):
                    items.append(_item("dmarc", "ok", "Email: DMARC record", "DMARC tells receiving mail systems what to do with mail that pretends to come from your domain.", f"Policy is p={d}.", None, 4))
        elif facts.get("domain_kind") == "platform":
            items.append(_item("email_na", "na", "Email records", "SPF and DMARC protect a domain's email.", "This address is on a hosting platform's own domain, so its email records are not yours to change.", None, 9))
        st = facts.get("security_txt")
        if st is not None:
            items.append(_item("security_txt", "ok" if st else "check", "A place to report problems (security.txt)",
                               "A small public file that tells researchers who to contact if they find a problem, so a report reaches you instead of staying quiet or going public.",
                               "Found." if st else "There is no /.well-known/security.txt.", (SECTXT_STEPS, SECTXT_CODE, SECTXT_PROMPT), 6))
        items.sort(key=lambda i: (0 if i["status"] == "check" else (1 if i["status"] == "ok" else 2), i["priority"]))
        n_check = sum(1 for i in items if i["status"] == "check") + (1 if header_fix else 0)
        n_ok = sum(1 for i in items if i["status"] == "ok")
        return {"has": True, "platform": plat, "platform_label": PLATFORM_LABELS[plat], "items": items, "header_fix": header_fix,
                "counts": {"check": n_check, "ok": n_ok},
                "note": ("These checks only read what any browser is sent, plus public DNS records. They don't try to get in, and they don't look for hidden files. "
                         "A check marked \"worth fixing\" is a suggestion for you to decide on, not a vulnerability report."),
                "prompt_note": "Paste a prompt into your AI builder and ask it to ADVISE first. Read its answer before you let it change anything."}
    except Exception:
        return {"has": False}


def render_html(facts, live=None):
    """The saved report page's Site setup panel, as HTML ('' when there is nothing to show). Everything is escaped."""
    try:
        v = view(facts, live)
        if not v.get("has"):
            return ""
        out = ['<div class="st">Site setup: what to fix</div><div class="card">']
        c = v["counts"]
        out.append(f'<div style="font-size:13px;line-height:1.6"><strong>{c["check"]} worth fixing, {c["ok"]} fine.</strong> '
                   f'This looks like it runs on {escape(v["platform_label"])}, so the steps below are for that.</div>')

        def fixblock(steps, code, prompt, intro=""):
            h = ""
            if intro:
                h += f'<div style="font-size:12.5px;font-weight:600;margin:.3rem 0">{escape(intro)}</div>'
            h += '<ol style="font-size:12.5px;line-height:1.6;margin:.2rem 0 .4rem 1.1rem;padding:0">' + "".join(f"<li>{escape(s)}</li>" for s in steps) + "</ol>"
            if code:
                h += f'<pre style="font-size:12px;background:#f4f3ee;border-radius:6px;padding:.5rem;overflow-x:auto;white-space:pre-wrap">{escape(code)}</pre>'
            if prompt:
                h += (f'<div style="font-size:12px;color:#6b6966;margin-top:.3rem">Or paste this into your AI builder:</div>'
                      f'<pre style="font-size:12px;background:#f4f3ee;border-radius:6px;padding:.5rem;overflow-x:auto;white-space:pre-wrap">{escape(prompt)}</pre>')
            return h
        if v["header_fix"]:
            hf = v["header_fix"]
            out.append('<details style="margin-top:.6rem"><summary style="cursor:pointer;font-size:13px;font-weight:600;color:#534AB7">&#8211; Security headers: how to fix</summary>'
                       + fixblock(hf["steps"], hf["code"], hf["prompt"], hf["intro"]) + "</details>")
        for it in v["items"]:
            mark = {"ok": ("&#10003;", "#1D9E75"), "check": ("&#8211;", "#92400E"), "na": ("&middot;", "#6b6966")}[it["status"]]
            head = (f'<span style="color:{mark[1]};font-weight:700">{mark[0]}</span> <strong style="font-size:13px">{escape(it["title"])}</strong>'
                    f'<span style="font-size:12.5px;color:#6b6966"> &mdash; {escape(it["detail"] or "")}</span>')
            if it["status"] == "check":
                out.append(f'<details style="margin-top:.6rem"><summary style="cursor:pointer">{head}</summary>'
                           f'<div style="font-size:12.5px;color:#4a4846;line-height:1.6;margin:.3rem 0">{escape(it["why"])}</div>'
                           + fixblock(it["steps"], it["code"], it["prompt"]) + "</details>")
            else:
                out.append(f'<div style="margin-top:.5rem">{head}</div>')
        out.append(f'<div style="font-size:12px;color:#6b6966;margin-top:.7rem">{escape(v["prompt_note"])} {escape(v["note"])}</div></div>')
        return "".join(out)
    except Exception:
        return ""
