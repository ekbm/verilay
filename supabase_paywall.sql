-- ============================================================================
-- Verilay — database changes for the paid deep scan
--
-- Run this once in the Supabase dashboard: SQL Editor → New query → paste → Run.
-- Everything is written so running it twice is harmless.
--
-- Two tables' worth of thinking, in one table plus one column:
--   purchases        who bought a deep scan of what, and until when
--   reports.user_id  which account a report belongs to (null = anonymous, i.e.
--                    every report that exists today)
--
-- Accounts themselves live in Supabase's own auth.users — we do not keep a
-- users table, because storing a second copy of an email address is a second
-- thing that can be wrong or leaked.
-- ============================================================================


-- ── purchases ────────────────────────────────────────────────────────────────
create table if not exists public.purchases (
  id                    uuid primary key default gen_random_uuid(),

  -- The idempotency key. Stripe cannot tell a lost reply from a failed one, so
  -- it retries webhooks — the same payment WILL arrive more than once. This
  -- being unique is what stops one payment becoming two purchases, and the
  -- insert failing on a retry is the normal path, not an error.
  stripe_event_id       text not null unique,

  stripe_session_id     text,
  stripe_payment_intent text,

  -- The email Stripe collected at checkout. The purchase is recorded against
  -- this before any account exists, and linked to user_id on first sign-in.
  -- Note this address is NOT verified by Stripe, which is exactly why paying
  -- does not sign anyone in — see entitlement_for_request in verilay_paywall.py.
  email                 text not null,
  user_id               uuid references auth.users(id) on delete set null,

  -- Normalised, lowercased owner/repo. One purchase, one app.
  repo                  text not null,

  amount_cents          integer,
  currency              text,

  created_at            timestamptz not null default now(),
  expires_at            timestamptz not null,

  -- Re-scans used. A quiet internal ceiling, never shown in the UI.
  scans_used            integer not null default 0,

  -- active | refunded | disputed
  status                text not null default 'active'
);

create index if not exists purchases_email_idx   on public.purchases (email);
create index if not exists purchases_user_idx    on public.purchases (user_id);
create index if not exists purchases_repo_idx    on public.purchases (repo);
-- The hot lookup: "is this person entitled to scan this app?"
create index if not exists purchases_lookup_idx  on public.purchases (email, repo, status);
create index if not exists purchases_pi_idx      on public.purchases (stripe_payment_intent);


-- ── Row level security ───────────────────────────────────────────────────────
-- RLS on with NO policy for anon means: nobody reaches this table except the
-- service role, which is what the server uses. That is deliberate. A purchases
-- table readable with the anon key would let anyone list every customer's email
-- address, and the anon key is by definition public.
--
-- If the app starts logging "[billing] Entitlement lookup FAILED", the cause is
-- almost certainly SUPABASE_KEY being the anon key rather than the service role
-- key. Fix the key — do not add a permissive policy here.
alter table public.purchases enable row level security;

-- One policy, so a signed-in customer could read their OWN purchases directly if
-- you ever add a client-side page. The server does not rely on this.
drop policy if exists "own purchases readable" on public.purchases;
create policy "own purchases readable"
  on public.purchases for select
  using (auth.uid() = user_id);


-- ── reports.user_id ──────────────────────────────────────────────────────────
-- Nullable, and null is the norm: the free tool has no accounts and every
-- existing row stays exactly as it is.
alter table public.reports
  add column if not exists user_id uuid references auth.users(id) on delete set null;

create index if not exists reports_user_idx on public.reports (user_id);


-- ── Check it worked ──────────────────────────────────────────────────────────
-- Should return one row for purchases and one for reports.user_id.
select 'purchases table' as thing, count(*)::text as detail
  from information_schema.tables
  where table_schema = 'public' and table_name = 'purchases'
union all
select 'reports.user_id column', count(*)::text
  from information_schema.columns
  where table_schema = 'public' and table_name = 'reports' and column_name = 'user_id';
