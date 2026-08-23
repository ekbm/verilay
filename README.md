# Verilay 🔍

**Understand what your AI-built app is actually made of.**

Verilay reads any GitHub repo, ZIP export, or live URL and generates a plain-English layer map — showing every part of your app (auth, database, API, libraries, config) with both an expert review and a beginner-friendly explanation, plus a second opinion export so you can verify findings independently.

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

**Ask Verilay** — ask a real question about your own report and get an answer grounded in your actual findings, not a generic response

**Production verdict** — is this app ready to ship?

**Fix list** — your top issues in priority order with ready-to-paste fix prompts for Lovable and Replit

**Second opinion prompts** — copy into Claude or ChatGPT for independent verification

> ⚠️ Scores may vary slightly between runs as findings are AI-generated. A meaningful improvement (e.g. C → B) after applying fixes indicates real progress. Verilay is a first-pass overview — not a penetration test or professional security audit.

### The deep scan (optional, paid)

The free analysis above covers the 25 files most likely to carry risk, and is free forever with no account needed. A one-time **$19 AUD deep scan** goes further: reads far more of your codebase, gives exact package names and fixes for every dependency vulnerability instead of just a count, and includes unlimited re-scans of the same app for 30 days so you can confirm a fix actually worked. See [verilay.dev/deep-scan](https://verilay.dev/deep-scan).

---

## Three ways to analyse your app

| Method | What you need | Analysis depth |
|--------|--------------|----------------|
| GitHub URL | Public repo URL | Full — all layers |
| ZIP upload | Export from Lovable/Replit | Full — all layers |
| Live URL | yourapp.lovable.app | Surface — visible layers only |

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
- `ANTHROPIC_API_KEY` — **required.** From https://console.anthropic.com. Each analysis costs approximately $0.01–0.03 in API credits.
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
Files sent to Claude API with structured analysis prompt
                    ↓
Claude classifies layers, identifies issues, writes plain-English explanations
                    ↓
Verilay renders interactive dashboard with Expert and Learner modes
                    ↓
Fix prompts generated — paste directly into Lovable or Replit to fix issues
```

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
