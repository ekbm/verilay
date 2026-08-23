# Verilay paywall — setup runbook

Everything needed to take the $19 deep scan from "code exists" to "money arrives".
Follow it in order. Nothing here can charge anybody until the very last step.

**The switch is `PAYWALL_ENABLED`. While it is `0`, `/deep-scan` says "coming
soon" and `/checkout` refuses to create a session.** Leave it at `0` until the
deep scan engine exists. Selling something that cannot be delivered is the one
mistake that would cost more than it earns.

---

## What was built

| File | What it does |
|---|---|
| `verilay_billing.py` | Stripe Checkout, webhook signature check, purchases, entitlement rules |
| `verilay_accounts.py` | Passwordless email sign-in via Supabase Auth, session cookie |
| `verilay_paywall.py` | The routes and pages: `/deep-scan`, `/checkout`, `/stripe-webhook`, `/login`, `/account`, `/deep/<owner>/<repo>` |
| `supabase_paywall.sql` | One new table (`purchases`) and one new column (`reports.user_id`) |
| `app.py` | Imports and registers the above; `SECRET_KEY` hardening; startup checks |
| `.env.example`, `requirements.txt` | New variables, and the `stripe` package |

New routes, all additions — no existing route changed behaviour:

```
GET  /deep-scan                 pricing page (or "coming soon" while the switch is off)
POST /checkout                  creates the Stripe Checkout session
GET  /checkout/success          confirms payment with Stripe, offers account setup
GET  /deep-scan?cancelled=1     they backed out; nothing charged
POST /stripe-webhook            the record of truth for "they paid"
GET  /login   POST /login       request a sign-in email
POST /auth/code                 sign in with the six-digit code
GET  /auth/callback             sign in from the emailed link
POST /auth/session              (used by the page above)
GET  /logout
GET  /account                   purchases and saved reports
GET  /deep/<owner>/<repo>       the deep scan — gated, engine live
GET  /billing-health            is everything wired up? no secrets in the output
```

---

## Step 1 — Supabase: run the migration

Dashboard → **SQL Editor** → New query → paste all of `supabase_paywall.sql` → Run.

It prints two rows at the end. Both counts should be `1`. Safe to run twice.

## Step 2 — Supabase: check which key the app uses

The `purchases` table has row level security on with no public policy, so **only
the service role key can read it**. If `SUPABASE_KEY` in Railway is the *anon*
key, every entitlement check will fail and the log will show
`[billing] Entitlement lookup FAILED`.

Dashboard → Settings → API. Confirm `SUPABASE_KEY` is the **service_role** key,
then also set **`SUPABASE_ANON_KEY`** to the anon/publishable key — sign-in uses
that one, and it should not be a key that can read every table.

Do not "fix" a failing entitlement lookup by adding a permissive policy to
`purchases`. That table holds every customer's email address, and the anon key is
public by design.

## Step 3 — Supabase: email that actually sends

Sign-in emails go out through Supabase Auth. Its built-in mailer allows only a
handful of emails per hour and is not for production — a customer would simply
never receive their link.

1. Sign up at **resend.com** (free tier: 100 emails/day, 3,000/month — far more
   than enough) and verify `verilay.dev` as a sending domain. That means adding
   the DNS records Resend gives you. Your DNS is at Cloudflare.
2. Supabase → Authentication → **Emails → SMTP Settings** → enable custom SMTP:
   - Host `smtp.resend.com`, Port `465`, Username `resend`,
     Password = your Resend API key
   - Sender email `noreply@verilay.dev`, Sender name `Verilay`
3. Supabase → Authentication → **URL Configuration**:
   - Site URL: `https://verilay.dev`
   - Redirect URLs: add `https://verilay.dev/auth/callback`
4. Supabase → Authentication → **Email Templates → Magic Link**. Make sure the
   template contains **both**:
   - `{{ .ConfirmationURL }}` — the link
   - `{{ .Token }}` — the six-digit code

   Both matter. The link is what most people click; the code is the fallback for
   anyone reading email on a different device, and it is the path that works
   entirely server-side.

Test it before going further: `/login`, enter your own address, and confirm the
email arrives and both the link and the code sign you in.

## Step 4 — Stripe: the product

You already have a Stripe account, so there is no verification wait.

Start in **test mode** (the toggle in the dashboard).

1. Products → **Add product**
   - Name: `Verilay Deep Scan`
   - Description: `A deep scan of your app, and re-scans whenever you like for 30 days.`
   - Price: **19.00 AUD**, **One off** (not recurring)
2. Copy the **price ID** (`price_...`) → that is `STRIPE_PRICE_ID`.

You can skip this entirely at first: with `STRIPE_PRICE_ID` blank the code creates
the price inline from `DEEP_SCAN_PRICE_CENTS` / `DEEP_SCAN_CURRENCY`, which is
handy for testing before the product exists.

## Step 5 — Stripe: a restricted key

Do **not** use the account secret key. This Stripe account is shared with your
other apps, so a leak from Verilay should not be able to touch them.

Developers → API keys → **Create restricted key**. Name it `verilay`. Permissions:

| Resource | Access |
|---|---|
| Checkout Sessions | **Write** |
| Payment Intents | Read |
| Products, Prices | Read |
| Customers | Write |
| Everything else | None |

Copy the `rk_test_...` value → `STRIPE_SECRET_KEY`.

## Step 6 — Stripe: the webhook

Developers → Webhooks → **Add endpoint**.

- URL: `https://verilay.dev/stripe-webhook`
- Events:
  - `checkout.session.completed`
  - `checkout.session.async_payment_succeeded`
  - `charge.refunded`
  - `charge.dispute.created`

Copy the endpoint's **signing secret** (`whsec_...`) → `STRIPE_WEBHOOK_SECRET`.
Each endpoint has its own; the test-mode one and the live-mode one are different,
and so is the Stripe CLI's.

## Step 7 — Railway: environment variables

```
SECRET_KEY              <64 random hex chars — see below>
SUPABASE_ANON_KEY       <anon key>
PAYWALL_ENABLED         0          ← leave at 0
STRIPE_SECRET_KEY       rk_test_...
STRIPE_WEBHOOK_SECRET   whsec_...
STRIPE_PRICE_ID         price_...  (or leave blank)
DEEP_SCAN_PRICE_CENTS   1900
DEEP_SCAN_CURRENCY      aud
BASE_URL                https://verilay.dev
```

Generate `SECRET_KEY` once and never change it:

```
py -c "import secrets; print(secrets.token_hex(32))"
```

**Why it matters.** It signs the sign-in cookie. Verilay used to fall back to a
random key, which was harmless when nothing used sessions. It is not harmless now:
Gunicorn runs four workers, each would invent its own key, and a signed-in
customer would be logged out whenever a request landed on a different worker.
Changing it later logs everyone out at once.

## Step 8 — Upload

Drag **all of these into one commit** — `app.py` alone would import modules that
are not there yet and take the site down:

```
app.py
verilay_billing.py
verilay_accounts.py
verilay_paywall.py
requirements.txt
.env.example
supabase_paywall.sql
PAYWALL_SETUP.md
```

Railway rebuilds and installs `stripe` from `requirements.txt`.

## Step 9 — Check the deploy

Visit **`https://verilay.dev/billing-health`**. It reports no secrets, only
whether each piece is present:

```json
{ "paywall_enabled": false, "stripe_key": true, "webhook_secret": true,
  "stripe_mode": "test", "auth_configured": true, "secret_key_set": true,
  "supabase": true, "sellable": false }
```

`sellable` stays `false` while the switch is off — that is correct.

Also check the Railway deploy log for:

```
✓ Paid path registered (paywall OFF — nothing for sale)
✓ Paywall OFF — deep scan not for sale (configuration looks complete)
```

If it lists things still to configure, it names each one.

Then confirm the free tool is untouched: run a normal analysis, open a report,
check `/blog` and `/privacy`.

---

## Testing the money path in test mode

Set `PAYWALL_ENABLED=1` **temporarily** (test-mode keys mean no real money can
move), then:

1. `/deep-scan` → enter `github.com/ekbm/verilay` → Continue to payment
2. On Stripe's page use card **`4242 4242 4242 4242`**, any future expiry, any CVC
3. You land on `/checkout/success` and can reach `/deep/ekbm/verilay`
4. Supabase → Table editor → `purchases` → one row, `repo` = `ekbm/verilay`,
   `expires_at` 30 days out
5. Stripe → Developers → Webhooks → your endpoint → the event shows **200**
6. Click **Resend** on that event. There must still be **one** row — the retry is
   recognised as a duplicate. (`/loop`-style retries are normal; Stripe cannot
   tell a lost reply from a failed one.)
7. Set up the account from the success page, sign in, check `/account` lists the
   purchase as Active
8. Sign out, then visit `/deep/ekbm/verilay` → refused, as it should be
9. Refund the payment in Stripe → `/deep/ekbm/verilay` refused, `purchases.status`
   now `refunded`

Cards for other cases: `4000 0000 0000 0002` declines, `4000 0025 0000 3155`
requires 3D Secure.

Then set `PAYWALL_ENABLED` back to `0`.

### Going live, later

Redo steps 4–6 with the dashboard in **live** mode — a live restricted key, a live
webhook endpoint with its own signing secret, and the product recreated. Test-mode
objects do not exist in live mode. `/billing-health` will report
`"stripe_mode": "live"`, and the startup log says `Stripe LIVE — real money`.

---

## Design decisions worth not undoing

**Paying does not sign you in.** Stripe collects an email at checkout but does not
verify it. If paying were enough to be "signed in", someone could check out with a
stranger's address and then see that stranger's reports. So a payment grants
access to *that purchase* (`paid_sid` in the session, set only after asking Stripe
whether the session was really paid), and being *signed in* requires clicking a
link or typing a code we emailed. Both paths are in `entitlement_for_request` in
`verilay_paywall.py` — that one function is the whole access-control story.

**The webhook is the record of truth, not the success redirect.** A redirect is
just the browser being told where to go; anyone can visit
`/checkout/success?session_id=whatever`. The webhook is signed with a secret only
Stripe and this server know. The success page does record a purchase if the
webhook has not landed yet, but it verifies with Stripe first and uses the session
id as the idempotency key so the webhook's later insert is recognised as the
duplicate it is.

**`stripe_event_id` is unique, and a duplicate insert is the normal path.** Stripe
retries deliberately. Without that constraint, one payment could become several
purchases, or several 30-day windows.

**A bad signature returns 400, an unreadable event returns 500.** Opposite
meanings: 400 tells Stripe to stop (it was not them), 500 tells Stripe to retry
(it was us). Collapsing them would either lose real payments or invite retry
storms from junk requests.

**Refunds and disputes revoke access** via `charge.refunded` /
`charge.dispute.created`. Without those events a refunded customer keeps their
entitlement.

**A quiet cap of 15 re-scans per purchase** (`MAX_SCANS_PER_PURCHASE`), never shown
in the UI. "Re-scan whenever you like" reads generously; "up to 15 re-scans" makes
people count. At 15–40c a scan, 15 of them is ~$2–6 against $19.

**One purchase, one app** — `normalise_repo` reduces every way of writing a repo
address to one lowercase `owner/repo`, so a buyer re-scanning the same app is
never asked to pay twice. It rejects `.` and `..`, which match the character rules
for a name but are path segments.

**Free stays free.** No route the free tool uses was changed. An anonymous
analysis inserts exactly the row it always did; `reports.user_id` is only set when
someone is signed in, and if that column is missing the report still saves,
unlinked.

---

## Not built yet

**The deep scan engine.** `/deep/<owner>/<repo>` checks the entitlement and then
says the engine is being built. That is the honest state, and it is why
`PAYWALL_ENABLED` must stay `0`.

The cheapest first version is not a new pipeline — it is the existing one with the
25-file cap raised and the extra Claude calls that implies, plus
`billing.consume_scan()` called once per run. A 300-file scan takes longer than a
web request survives, which is what the job row and a `/job/<id>` polling page are
for.

**Nothing charges GST.** If you are registered, enable Stripe Tax and add your
ABN. Worth checking before live mode.

**`/terms` and `/privacy` still describe a free tool with no accounts.** Both need
a paragraph on paid purchases, refunds, and the fact that an account now exists —
before, not after, the first sale.

**Rate limiting is still per worker.** Four Gunicorn workers each keep their own
counter, so 10/hour is really up to 40/hour. Unrelated to billing, still open.
