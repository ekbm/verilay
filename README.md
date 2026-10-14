# Verilay 🔍

**Understand what your AI-built app is actually made of.**

Verilay reads any public GitHub repo, ZIP export, or live URL and generates a plain-English layer map — showing every part of your app (auth, database, API, libraries, config) with both an expert review and a beginner-friendly explanation, plus a second opinion export so you can verify findings independently.

Built for the 99% of people who build with AI tools like Lovable, Replit, and Emergent — but can't verify what was generated.

🌐 **Live at [verilay.dev](https://verilay.dev) — free, no account needed**

---

## The problem Verilay solves

You used Lovable or Replit to build an app. It works — but:

- Is your login system actually secure?
- Are your database credentials exposed?
- What libraries are you using and are they safe?
- Is this app ready for real users?
- What does any of it actually do?

Tools like CodeRabbit and Snyk answer these questions — for developers, in developer language. **Verilay answers them for everyone else.**

---

## What Verilay gives you

**Stack map** — every framework, library, and tool detected with plain-English descriptions

**Architecture diagram** — a visual map of your app's layers and how they connect, labelled specific to what you actually built, with a plain-English breakdown of what each part does

**Layer map** — your app broken into Auth, Database, API, Frontend, Libraries and Config

**Two view modes per layer:**
- **Expert** — technical findings with severity, file references and specific issues
- **Learner** — plain-English explanations, real-world analogies and key concepts

**Verified secret scan** — every file checked directly for exposed API keys, passwords and database logins. Not a sample, not AI-guessed — a fact.

**Dependency vulnerability check** — every dependency checked against OSV.dev, a public database of known security issues

**Weak cryptography check** — your files are checked directly for weak or hard-coded cryptography, not guessed by the AI

**Who can see your data (Supabase apps)** — Verilay reads your database rules and backend functions and tells you, in plain English, where anyone on the internet could read or change something they shouldn't. The free scan shows a count; the deep scan lists each one with a fix. Settings changed only in the Supabase dashboard can't be seen from your files.

**Closest similar project** — the free scan shows the closest open-source project doing something like yours. The deep scan lists up to six, with why each is similar, what it's best at, its licence and when it was last updated, so you can learn from one, build on it, or get in touch with the people behind it. It searches free, open-source projects on GitHub only, not commercial apps, so "no match" never means nothing similar exists.

**IT Review Pack** — a printable checklist for IT teams deciding whether to approve an app a colleague built with AI

**Ask Verilay** — ask a real question about your own report and get an answer grounded in your actual findings, not a generic response

**Production verdict** — is this app ready to ship?

**Fix list** — your top issues in priority order with ready-to-paste fix prompts for Lovable and Replit

**Second opinion prompts** — copy into Claude or ChatGPT for independent verification

> ⚠️ Scores may vary slightly between runs as findings are AI-generated. A meaningful improvement (e.g. C → B) after applying fixes indicates real progress. Verilay is a first-pass overview — not a penetration test or professional security audit.

### The deep scan (optional, paid)

The free analysis above covers the 25 files most likely to carry risk, and is free forever with no account needed. A one-time **$19 AUD deep scan** goes further:

- **Reads up to 150 files** instead of 25
- **A "fix these first" list**, in priority order, each with a plain-English explanation and a ready-to-paste prompt for your AI builder
- **Every risky package named**, with its exact version and vulnerability ID, plus one fix prompt per package and one to update them all
- **Each access problem listed** for Supabase apps, with a fix, instead of just a count
- **Up to six similar open-source projects** to learn from or partner with
- **Unlimited re-scans of the same app for 30 days**, so you can confirm a fix actually worked
- **Saved in your account**

If part of your app couldn't be read, the deep scan report says "Not checked" for that part instead of showing a green tick. It reads public GitHub repositories only, and it is an automated first pass, not a penetration test. See [verilay.dev/deep-scan](https://verilay.dev/deep-scan).

---

## Three ways to analyse your app

| Method | What you need | Analysis depth |
|--------|--------------|----------------|
| GitHub URL | Public repo URL | Full — all layers |
| ZIP upload | Export from Lovable/Replit | Full — all layers |
| Live URL | yourapp.lovable.app | Surface — visible layers only |

Verilay reads **public** GitHub repositories only, and it never writes to your repository. You decide which fixes to apply, using your own AI builder.

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/ekbm/verilay
cd verilay
pip install -r requirements.txt
```

### 2. Set up your API keys

```bash
cp .env.example .env
```

Edit `.env` and add:
- `ANTHROPIC_API_KEY` — **required.** From https://console.anthropic.com. Each analysis makes several AI calls: a few cents for a small app, and more for a very large one.
- `GITHUB_TOKEN` — optional but recommended. Free from https://github.com/settings/tokens (read-only scope). Without it: 60 GitHub API requests/hour. With it: 5,000/hour.

That's everything needed for the free analysis tool to run locally. `.env.example` also lists variables for the deep scan, accounts, and Stripe — those are all optional, and the app runs fine without them (the paid path just doesn't load). See [PAYWALL_SETUP.md](PAYWALL_SETUP.md) if you want to set those up too.

### 3. Run Verilay

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

---

## How it works

```
You provide a GitHub URL, ZIP file, or live app URL
                    ↓
Verilay reads priority files (auth, DB, config, routes...)
                    ↓
Fixed checks run on your files: exposed secrets, weak cryptography,
known-vulnerable packages (OSV.dev), and database access rules
                    ↓
The files most relevant to each layer are sent to the Claude API
                    ↓
Claude classifies layers, identifies issues, writes plain-English explanations
                    ↓
Verilay renders interactive dashboard with Expert and Learner modes
                    ↓
Fix prompts generated — paste directly into Lovable or Replit to fix issues
```

---

## Sharing and privacy

- A report is shared by its link. Anyone who has the link can open it, so don't send it to someone you wouldn't show the code to. Reports are not listed anywhere, and search engines are told to ignore them.
- Only the browser that ran a scan (or, for a deep scan, you, when signed in) can change or delete that report.
- Reports from a free analysis stop working 90 days after the scan. Deep scan reports are kept in your account.
- Verilay reads public repositories only.

---

## Supported platforms

Designed for apps built with:
- **Lovable** — React + Supabase stack
- **Replit** — Python/Node.js stack
- **Bolt, v0, Cursor** — any AI builder
- Any public GitHub repository

---

## Why open source?

Verilay is a trust and validation tool. Being open source means anyone can inspect Verilay's own code — which is the most honest thing a trust product can do.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what's shipped and what's next.

---

## Contributing

Verilay is open source and welcomes contributions.

- Found a bug → open an issue
- Want to add a feature → open a PR
- Want to help build → reach out at moses@verilay.dev

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Licence

**Personal & open source use:** Free — see [LICENSE.md](LICENSE.md)

**Commercial use:** If you want to embed Verilay in a commercial product or offer its functionality to paying customers, a commercial licence is required.

📧 Contact **moses@verilay.dev** with subject "Commercial Licence Enquiry"

---

*Built in Perth, Australia. For the 99% of people who build real things with AI tools and deserve to understand what they built.*

## Forking & Reuse

If you're thinking about forking Verilay — you're welcome to explore the code.

Before you fork, please consider reaching out first at **moses@verilay.dev** with what you're planning to build and whether it's personal, open source, or commercial.

This isn't a legal requirement for personal or open source forks — but it helps avoid duplicated effort and we may be able to collaborate instead.

**Commercial use** always requires a commercial licence. See [LICENSE.md](LICENSE.md).
