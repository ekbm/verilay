Verilay 1.0: free scans, deep scans, and a private-repository beta

Verilay reads an app built with an AI tool and explains, in plain English, what it is made of and where it may be unsafe. It is made for people who build with AI but are not developers.

Live at https://verilay.dev. Free, no account needed.

## What is in this release

**Free scan**
- Paste a public GitHub link, upload a ZIP of your project, or enter a live address.
- A layer map of your app (sign-in, database, API, front end, libraries), in plain English.
- Findings written for non-developers, each with short, safe steps to check it yourself.
- Checks that do not depend on an AI's opinion: secrets left in code, libraries with known vulnerabilities, and access rules.
- Honest labels: "no issues seen", "Nothing found", "Check required". A live address is shown as a preview and is never graded, because a scan from outside cannot see the backend.

**Deep scan** (A$19, one repository)
- A fuller review of the code, with fix prompts and re-scans for 30 days.

**Private repositories (free beta)**
- Connect one private GitHub repository with read-only access. Verilay reads its code once and then removes its own access. The report is private to your browser and is removed after 30 days. Daily limits apply.

**Also**
- A free security checklist for apps built with AI: https://verilay.dev/checklist
- A directory of checked apps built with AI tools: https://verilay.dev/apps
- "What we keep": a ZIP is read during the scan and is not saved. A report keeps the findings, the score and file names, never your project's files. A free report's link works for 90 days and can be deleted. Full detail: https://verilay.dev/privacy

Every change, in plain English: https://verilay.dev/changelog

## Licence
Free for personal, educational and open source use. A commercial licence is needed to build Verilay into a commercial product. See LICENSE.md, or write to moses@verilay.dev.
