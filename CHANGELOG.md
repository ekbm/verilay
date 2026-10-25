# Changelog

Every improvement, fix and new feature of Verilay, in plain English, newest first. The same list is on the site: https://verilay.dev/changelog

## October 25, 2026: Compare with your last scan

`New`

**New:** scan the same app again and Verilay offers to compare the two: what is no longer found, what is still there and what is new, plus the grade before and after. Only scans made in your browser, or by your account, can be compared, and the comparison is saved on the new report. It says “no longer found”, not “fixed”, and warns you when the two scans read different files.

**Good to know:** when you sign in, the reports this browser made earlier are linked to your account, so they stay on your account page. The [privacy page](https://verilay.dev/privacy) says so.

**New:** signed in, you can compare with scans from your account on any device. And when a comparison shows your app improved, you can tell us what you changed. It is optional, never shown on your report, and only quoted if you say so.

## October 25, 2026: No grade from an answer that did not arrive

`Fix` · `Improve`

**Fixed:** if the AI review of an area of your app comes back empty or unreadable, Verilay now tries once more, and if it still cannot read it, marks that area “Not checked” and gives no grade. Before, such an area could show as “No issues found” and lift the grade.

**Improved:** the key check now finds Supabase’s newer secret keys (they start with sb_secret_). The publishable key, which is meant for the browser, is never flagged.

## October 24, 2026: A fuller dependency check, counted per package

`Fix` · `Improve`

**Fixed:** when the public vulnerability database does not answer, the report now says the check could not be completed. Before, that could read as “no known vulnerabilities”.

**Improved:** Verilay now describes every known problem it finds, not only the first few, and checks each version of a package your app uses. It reads more package lists: yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock, Pipfile.lock and Bun’s text lockfile (bun.lock). Bun’s older binary bun.lockb cannot be read, and the report says so.

**Improved:** the numbers and the grade now count packages, not separate advisories. One old library with 57 known problems is one thing to fix, so it counts once. Every advisory is still listed in the detail, and packages used only while building the app still do not count. Apps with a large package list will often show more known problems than before, because more of the list is now read.

## October 23, 2026: Live-address scans now say how to fix the site’s setup

`New` · `Improve`

**New:** a scan of a live address now has a “Site setup” section. It checks whether plain http is sent on to https, how long the certificate lasts, whether sign-in cookies are protected, whether the server announces what software it runs, the email records (SPF and DMARC) of your own domain, and whether there is a security.txt file telling researchers where to report a problem. Anything that needs attention comes with plain steps for the host the site seems to run on, and a prompt you can paste into your AI builder.

**Improved:** the security headers now come with one fix for all the ones that are missing, with the exact code for hosts such as Express, Flask, Vercel and Netlify. It only reads what any browser is sent, plus public DNS records. It never looks for hidden files, and the result is still a checklist, not a grade. The [privacy page](https://verilay.dev/privacy) says exactly what is looked up.

## October 20, 2026: Private repositories: a free beta

`New`

**New:** you can now check a private GitHub repository. Connect one repository with read-only access, and Verilay reads its code once, then removes its own access to your account. The report is private to your browser and is removed after 30 days. It is a free beta, with daily limits for each GitHub account.

**Good to know:** a ZIP upload still works for private code and keeps your project entirely under your control. The [privacy page](https://verilay.dev/privacy) says exactly what is kept.

## October 20, 2026: A free security checklist, and a fuller preview for live-site scans

`New` · `Improve` · `Fix`

**New:** a free [vibe coding security checklist](https://verilay.dev/checklist): ten plain questions to ask before real users or payments arrive, each with a way to check it yourself and an honest note on how much Verilay covers it. There is a [blog post](https://verilay.dev/blog/10-point-security-checklist-ai-built-app) to go with it.

**Improved:** a scan of a live address now shows the security headers the site sends, the outside scripts its page loads, six tests you can try yourself, and how to get a full review of your code. The score cards show dashes instead of the word “None”, and the file count leaves out Verilay’s own note files.

**Fixed:** a live-address result no longer says “Analysing” for ever. It says the layer breakdown needs your code (a GitHub link or a ZIP).

## October 19, 2026: What Verilay keeps, in plain words

`New` · `Improve`

**New:** a short “What we keep” note under the Upload ZIP box. A ZIP is read while the scan runs and is not saved. A report keeps the findings, the score and file names, never your project’s files. The code is analysed by Claude, an AI service made by Anthropic. A free report’s link works for 90 days and can be deleted.

**Improved:** the [privacy page](https://verilay.dev/privacy) now says the same, lists the services that help run Verilay, and describes how your IP address is used.

**Improved:** the Ask Verilay question box no longer saves your IP address. It keeps a scrambled counter for the free-question limit, and old counters are deleted automatically.

## October 18, 2026: Plainer results, and steps to check each finding yourself

`New` · `Improve`

**New:** “Check it yourself”: under each finding, a few short, safe steps you can try on your own app, such as opening a private window to see whether a page needs a login, using two test accounts, or typing an apostrophe into a search box. Each says what a good and a bad result look like. Where a finding needs an experienced person, it says so.

**Improved:** “passing” now reads “no issues seen” (“Nothing found” in the IT review, and “Check required” when a person should look). To a non-developer, “passing” sounds like “all clear”, and a scan can’t promise that.

**Improved:** a scan of a live address is never graded, however many files the site sends. A scan from outside can’t see the backend, so it shows “Preview, not graded” and points to a GitHub link or ZIP for a real review.

**Improved:** the weak-encryption check now works across more languages, points out when a weak hash sits in one file and passwords are handled in another, and every area that shows no issues says why and what was not checked.

## October 17, 2026: A clearer home page, labelled fixes, and a quick view of what was checked

`New` · `Improve`

**New:** a home page with the scan box right at the top, an example report, and the story of why Verilay exists. A “Scan at a glance” panel in every report shows what each check covered, in numbers.

**Improved:** each fix now says which part of your app and which technology it is about, and the packages card points to the right fix. Private keys pasted inside strings in code are now found.

**New:** a page where you can tell me you’d like to scan private repositories, so I know whether it is worth building.

## October 16, 2026: Checked apps: a directory for apps built with AI, and a stamp for yours

`New` · `Improve`

**New:** [Checked apps](https://verilay.dev/apps), a free directory of apps built with AI tools. After a free scan of a public GitHub app, choose “List my app”. Each app gets its own page, and visitors can search, filter by the tool it was built with, and contact the builder. Builders’ email addresses are never shown: messages are passed on by email.

**New:** apps whose scan finds no critical issues and grades A or B get a green “Checked” stamp, dated, with code to put it on their own site. It turns amber after 90 days until the app is checked again.

**Improved:** the menu has a “Checked apps” link, and the phone menu is shorter: Privacy, Terms and AI Disclaimer are in the footer. [Why I built it](https://verilay.dev/blog/560000-new-apps-how-yours-gets-noticed).

## October 14, 2026: Report links expire, and repeat scans are quicker

`New` · `Improve`

**New:** the link to a free report now works for 90 days, and each report shows the date it stops. Deep scan reports stay in your account for as long as you keep it.

**Improved:** scanning the same public app again within a day, with no new changes to its code, now answers in seconds and says the analysis was reused. When Verilay is very busy it asks you to try again in a minute instead of slowing everyone down, and that attempt does not count against your hourly allowance. Only public GitHub repositories can be scanned from the website.

**Improved:** apps with all their code in a few files, and no folders called auth or routes, are now read properly. Login, database, settings and page code is found by what it does, not by what the file is called, so fewer areas come back as “Not checked”.

**Fixed:** in a deep scan, an area with nothing wrong could be labelled “Not checked”. It now describes what Verilay found there, and “Not checked” is kept for areas it really did not see.

## October 12, 2026: Safer reports, clearer results, and scan dates

`Fix` · `Improve` · `New`

**Fixed:** Delete report now really deletes.

**Improved:** a report can only be changed or deleted from the browser that ran the scan, or by you when signed in. Older reports are now read-only; to have one removed, email moses@verilay.dev. Reports now say which packages were checked, and the results page is easier to read, with sections that open and close. [More on the report changes](https://verilay.dev/blog/anyone-with-the-link-safe-verilay-report-security).

**New:** every report shows when it was scanned (UTC). For Supabase apps, Verilay now checks who can do what in your database and backend functions: the free scan shows the count, the deep scan lists each one with a fix.

## October 10, 2026: Similar projects, a clearer deep scan report, and a smoother account page

`New` · `Improve` · `Fix`

**New:** every free scan of a GitHub app now shows the closest similar open-source project, a quick way to see what already exists before you build more of the same. The deep scan lists up to six, with what each one is best at. These come from free, open-source projects on GitHub only, not commercial apps, so no match never means nothing similar exists.

**Improved:** on a deep scan report the fixes now sit right after your score instead of at the bottom, each with a Copy button. Instead of one long list of advisories you get one fix per package, with a ready-to-paste prompt for your AI builder and a single prompt to update everything.

**Improved:** when Verilay never saw any code for a layer (for example Auth or Config), that layer now says “Not checked” instead of “Passing”.

**Fixed:** a vulnerability in a build or test tool, which never ships to your users, can no longer push a report to critical. It still shows as a warning.

**Fixed:** the version Verilay tells you to update a package to now matches the version your app actually uses. Before, some suggestions pointed to an older version or a bigger upgrade than needed.

**New:** deep scan reports are now labelled and listed separately from free reports in your account, and every report has a Quick scan link that opens the homepage with your repository already filled in.

**Improved:** links to verilay.dev and to reports now show a proper preview when shared on LinkedIn, WhatsApp or Slack, and report pages are kept out of search engines. The Analyse button also sits higher on phones, and the Verilay logo is now the same on report, sign-in and payment pages.

**Fixed:** on phones, the sign-off section of the IT Review Pack no longer runs off the edge of the screen.

**Improved:** the “issues resolved” figure in the homepage monitoring line now counts only specific issues we recorded as fixed, not a drop in totals (which the AI wording a finding differently could cause). Until fixes are recorded it shows nothing.

**Improved:** privacy-friendly page-view counts (no cookies) now cover more pages, so we can see which ones are useful.

## October 5, 2026: IT Review Pack, ZIP uploads fixed, and reliable report links

`New` · `Fix` · `Improve`

**New:** every report now has an IT Review Pack — a printable checklist for IT teams deciding whether to approve an app a colleague built with AI. It shows a suggested decision, the repeatable checks and the AI review side by side, what to fix first, what the review did not check, and a sign-off box. Risk reduced and reviewed, not certified safe.

**Fixed:** ZIP uploads were failing with an error before any results appeared. They work again.

**Fixed:** shared report links sometimes showed “Report not found”, and the apps-analysed count on the homepage could briefly show 0. A connection to Verilay’s database was being dropped and not reopened. It now reconnects automatically, and report links load every time.

**Improved:** ZIP scans now check every file for exposed keys, weak cryptography and vulnerable libraries — including `.env` and lockfiles — the same way GitHub scans do. Your uploaded code is read in memory only and never saved.

## September 15, 2026: Cleaner account page, works properly on mobile

`Improve`

Your reports and purchased deep scans now live in clean, collapsible sections — tap to expand just the one you need. The page also finally uses the full width of the screen instead of a narrow centre column, and every link opens in its own tab so you never lose your place.

## September 15, 2026: New: crypto hygiene checks

`New`

Verilay now checks for weak password hashing, insecure encryption modes, hardcoded encryption keys, and undersized RSA keys — reported alongside your existing findings, with the same plain-English explanations.

## September 15, 2026: More precise dependency risk scoring

`Improve`

Dependency findings are now weighted more precisely against the public vulnerability database, and build-only tools (your test runner, bundler, and similar) no longer count toward your critical/warning score the way a real runtime dependency does — verified against an independent second opinion from another AI tool on a real app.

## August 21, 2026: See your app's structure in one picture

`New`

Every report now includes a visual map of your app — Auth, Database, API, Frontend and more, laid out and labelled specific to what you actually built, not generic categories. A plain-English breakdown of what each part does sits right underneath.

## August 21, 2026: Ask Verilay now knows your actual results

`New`

Ask a real question about your report — "why is this critical?" or "how do I fix the database one?" — and get an answer grounded in your actual scan, not a generic response. Right there on the report page.

## August 21, 2026: See how far along your analysis is

`Improve`

While your scan is running, you'll now see a real progress indicator and a clear note that nothing needs your input — instead of just a spinner and no sense of how much longer it'll take.

## August 21, 2026: More reliable on large repos, and more complete findings

`Fix`

Bigger repositories now scan reliably instead of occasionally failing with a "try ZIP" error. Findings also come back more complete — a token-limit issue was occasionally cutting an analysis short partway through.

## August 19, 2026: The deep scan is here

`New`

A one-off, deeper review of your app for $19 AUD plus applicable tax: reads far more of your code than the free scan, gives exact package names and fixes for every dependency vulnerability, and includes unlimited re-scans of the same app for 30 days so you can confirm a fix actually worked. Runs in the background — close the tab and come back, your report is saved and waiting when it's done.

## August 19, 2026: Sign in and pricing, right on the homepage

`Improve`

If you've bought a deep scan, there's now a quiet Sign in link on the homepage so you don't have to hunt for the URL to see your saved reports. A Pricing link now points to the full free-vs-deep-scan comparison too.

## August 18, 2026: More specific recommended fixes

`Improve`

The Recommended Fixes and Second Opinion sections now reference your actual findings rather than just a summary — more useful, specific guidance instead of one generic suggestion.

## August 18, 2026: Score could look different mid-analysis than in your saved report

`Fix`

In some cases the critical/warning counts shown while your analysis was still running didn't match what got saved to your report afterward. Both now always agree.

## August 18, 2026: Dependency vulnerability count is now accurate

`Fix`

A vulnerability that's catalogued under two different public reference numbers was being counted twice, making the total look worse than it really is. Each one is now counted once.

## August 18, 2026: Checks your dependencies for known security problems

`New`

Every scan — including the free one — now checks the code libraries your app depends on against OSV.dev, a public database of documented security vulnerabilities. If something's affected, you'll see how many issues were found; the deep scan shows exactly which ones and how to fix them.

## August 18, 2026: Saved reports now show your full security findings

`Fix`

Reopening a report you'd saved or shared previously left out the exposed-keys check and the dependency check, even though they'd run. Both now show up properly whenever you come back to a report, not just the moment it first finishes.

## August 9, 2026: See what your app is made of

`New`

Reports now include a plain-English breakdown of your whole app — grouping every file into simple categories like visual pages, data & logins, settings and building blocks. It shows that most of an app is safe internal machinery, and that the parts which matter for security are a smaller set — the ones Verilay checks first. There's a simple view for non-developers and a developer view for more technical detail.

## June 21, 2026: Reads much more of your code

`Fix` · `Improve`

Verilay now reads far more of each file before grading. Previously, large single-file apps could be cut short, so the scan sometimes only saw the styling and missed the JavaScript or backend logic further down — occasionally misreading a working app as an incomplete one. Your scans now take in much more of the actual code, so the analysis is based on what your app really does.

## June 16, 2026

`Improve`

Re-running the same app now gives you the same grade. Your score is calculated directly from the findings, so the headline grade and verdict always match the detailed results below them.

## June 16, 2026: See exactly what was analysed

`New`

Every report now shows how many of your files were analysed, with the full list a click away — so you always know precisely what the scan covered.

## June 16, 2026: Clearer guidance on every finding

`Improve`

Every critical issue now gets its own advice prompt, with the most important issues listed first — so you always know what to tackle, and in what order.

## June 14, 2026: Minified production code no longer flagged

`Fix` · `Improve`

Verilay no longer treats minified or bundled JavaScript as a problem. Shipping minified code is how every production app is built — it's a sign things are working, not a security risk. It will never lower your score or show as a warning again.

## June 10, 2026: Blog, Privacy, Terms and About pages

`New` · `New` · `New`

Added Blog at /blog, Privacy policy, Terms of use with AI disclaimer, About page with the story behind Verilay, and this Changelog. Verilay now feels like a proper product.

## June 9, 2026: Advice-first prompts — investigate before fixing

`Feature` · `Improve`

All fix prompts changed to advice prompts. Every prompt now asks your AI builder to investigate and advise before making any changes. "Copy fix prompt" became "Get advice prompt". "Fix in Lovable" became "Ask Lovable about this". Safety warning added before copying.

## June 9, 2026: Verify findings with your AI builder

`Feature`

Mark any finding as verified by pasting your AI builder's response. Score recalculates based on unverified findings only. Layer dots turn green when all findings are verified. Report becomes a living document.

## June 8, 2026: Smart file selection + dependency awareness

`Improve`

Verilay now reads package.json first to identify your exact stack before analysing. Files are selected by security relevance not just filename. Added awareness for Drizzle ORM, NextAuth, Clerk, Prisma, Flask, Gunicorn and more.

## June 7, 2026: Waitlist capture + score A/B/C guide

`New` · `Improve`

Waitlist popup after 3 analyses to capture demand for Pro features. Score guide now shows exactly what's needed to reach each grade — including a checklist to go from B to A.

## June 5, 2026: Learner mode + unique app-specific analogies

`New` · `Improve`

Learner mode explains each layer in plain English with analogies specific to your app. A travel app gets travel analogies. A legal app gets legal analogies. Never generic "think of it like a bouncer" explanations.

## May 28, 2026: Platform awareness for Lovable, Replit, Supabase

`Fix` · `Improve`

Added 30+ platform-specific rules to prevent false positives. Supabase anon keys, Replit OIDC auth, Lovable auto-managed env vars and TanStack Query patterns are now correctly recognised as valid — never flagged.

## May 20, 2026: 🚀 Verilay launched

`New`

First public release. GitHub and URL analysis, plain-English security reports, layer map with Expert and Learner modes. Free, no login required.
