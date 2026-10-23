-- ============================================================================
-- Verilay: the free daily look at each monitored app's LIVE site (verilay_livewatch.py)
--
-- Run this once in the Supabase dashboard: SQL Editor, New query, paste, Run. Running it twice is harmless.
-- It only ADDS three columns to the table that already exists, so no grant is needed (the server already has access to it).
--
--   live_url          the https address of the app's live site (empty = not checked)
--   live_checked_at   when it was last looked at (the claim that stops two workers checking the same app)
--   live_state        what the last check saw: headers, https redirect, certificate days
-- ============================================================================
alter table public.self_monitoring
  add column if not exists live_url text,
  add column if not exists live_checked_at timestamptz not null default '2000-01-01',
  add column if not exists live_state jsonb;

-- Set each app's live address (edit the names and addresses to match your rows, then run them):
-- update public.self_monitoring set live_url = 'https://verilay.dev'    where app_name = 'Verilay';
-- update public.self_monitoring set live_url = 'https://buildbook.au'   where app_name = 'BuildBook';
-- update public.self_monitoring set live_url = 'https://loginsight.app' where app_name = 'Loginsight';

-- Check it worked: one row per app, with its live address.
select app_name, live_url, live_checked_at from public.self_monitoring order by app_name;
