-- Verilay: A$2.99 fix-prompt unlocks (verilay_prompts.py, from 1 Dec 2026). Run once in the Supabase SQL editor.
-- One row per paid unlock: every fix prompt for one app (app_key), for 7 days. Written and read only by the Verilay
-- server. Row-level security is ON with no policies, so the public (anon) key cannot read or write it.

create table if not exists prompt_unlocks (
  id                     bigint generated always as identity primary key,
  stripe_session_id      text        not null unique,
  stripe_event_id        text,
  stripe_payment_intent  text,
  report_id              text        not null,
  app_key                text        not null,
  email                  text,
  amount_cents           integer,
  currency               text,
  status                 text        not null default 'active',
  expires_at             timestamptz not null,
  created_at             timestamptz not null default now()
);

create index if not exists prompt_unlocks_app_key_idx on prompt_unlocks (app_key);
create index if not exists prompt_unlocks_report_idx on prompt_unlocks (report_id);

alter table prompt_unlocks enable row level security;

-- Since 30 Oct 2026 Supabase no longer gives new tables to the API roles automatically: the server's key needs an
-- explicit grant (the anon and authenticated roles get nothing).
grant select, insert, update on table prompt_unlocks to service_role;
