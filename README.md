# Verilay 🔍

**Understand what your AI-built app is actually made of.**

Verilay reads any GitHub repo, ZIP export, or live URL and generates a plain-English layer map — showing every part of your app (auth, database, API, libraries, config) with both an expert review and a beginner-friendly explanation, plus a second opinion export so you can verify findings independently.

Built for the 99% of people who build with AI tools like Lovable, Replit, and Emergent — but can't verify what was generated.

---

## The problem Verilay solves

You used Lovable or Replit to build an app. It works — but:

- Is your login system actually secure?
- Are your database credentials exposed?
- What libraries are you using and are they safe?
- Is this app ready for real users?
- What does any of it actually do?

Tools like CodeRabbit and Greptile answer these questions — for developers, in developer language. **Verilay answers them for everyone else.**

---

## What Verilay gives you

**Stack map** — every framework, library, and tool detected with plain-English descriptions

**Layer map** — your app broken into Auth, Database, API, Frontend, Libraries, Config, and File Handling

**Three view modes per layer:**
- **Expert** — technical findings with severity, file references, and code snippets to verify
- **Learner** — plain-English explanations, real-world analogies, and "why it matters"
- **Quiz** — quick-check questions to test whether the understanding actually stuck

**Production verdict** — green/amber/red banner: is this app ready to ship?

**Fix list** — your top issues in priority order with effort estimates and specific steps

**Second opinion export** — ready-made prompts to copy into Claude, ChatGPT, or share with a developer for independent verification

**Security checklist** — exposed secrets, auth configuration, RLS policies, dependency currency

---

## Three ways to analyse your app

| Method | What you need | Analysis depth |
|--------|--------------|----------------|
| GitHub URL | Public repo URL | Full — all layers |
| ZIP upload | Export from Lovable/Replit | Full — all layers |
| Live URL | yourapp.lovable.app | Surface — libraries only |

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
- `GITHUB_TOKEN` — free from https://github.com/settings/tokens (read-only scope)
- `ANTHROPIC_API_KEY` — from https://console.anthropic.com

Each analysis costs approximately **$0.01–0.03** in API credits.

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
Verilay renders interactive dashboard with Expert / Learner / Quiz modes
                    ↓
Second opinion prompts generated — verify findings in any AI tool
```

---

## Supported platforms

Designed for apps built with:
- **Lovable** — React + Supabase stack
- **Replit** — Python/Node.js stack  
- **Emergent** — full-stack apps
- Any public GitHub repository

---

## Why open source?

Verilay is a trust and validation tool. Being open source means anyone can inspect Verilay's own code — which is the most honest thing a trust product can do. We don't hide our reasoning.

---

## Roadmap

- [ ] Hosted version at verilay.dev — no Python install needed
- [ ] Private repo support via GitHub OAuth
- [ ] Live mode — webhook updates as you build in Lovable
- [ ] Chrome extension — Verilay panel inside Lovable and Replit
- [ ] Shareable report links
- [ ] Snyk integration for CVE data on dependencies
- [ ] Comparison mode — two repos side by side

---

## Contributing

Verilay is open source and welcomes contributions.

- Found a bug → open an issue
- Want to add a feature → open a PR
- Want to help build the hosted version → reach out

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — use it, fork it, build on it.

---

*Built in Perth, Australia. For the 99% of people who build real things with AI tools and deserve to understand what they built.*
