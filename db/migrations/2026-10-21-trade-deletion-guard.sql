-- ═══════════════════════════════════════════════════════════════════════
--  MackH Journal — trade deletion guard
--
--  Why: a save that was sent before a delete (and arrived late, e.g. after
--  a client timeout) could re-create the deleted trade. With this migration
--  the database remembers deletions and refuses a late save atomically.
--
--  What it does:
--   1. trades.deleted_at — when the trade was deleted (NULL = active).
--   2. mj_save_trade()   — insert/update a trade unless it is deleted;
--                          p_restore = true (explicit "Undo") clears the mark.
--   3. mj_delete_trade() — marks a trade deleted and wipes its content
--                          (data and img_url); only id, owner and the date stay.
--                          Works even if the trade has not reached the server yet.
--   4. Only the server (service_role) may call the functions.
--
--  How to run: Supabase → SQL Editor → paste this file → Run. Safe to run
--  again (idempotent). Make a backup first (see db/DEPLOY-trade-deletion-guard.md).
--  The app keeps working before and after: server.js detects the column.
-- ═══════════════════════════════════════════════════════════════════════

begin;

alter table public.trades add column if not exists deleted_at timestamptz;

create or replace function public.mj_save_trade(
  p_id      public.trades.id%type,
  p_user_id public.trades.user_id%type,
  p_data    public.trades.data%type,
  p_img_url public.trades.img_url%type,
  p_restore boolean default false
) returns text
language plpgsql
set search_path = public
as $$
declare
  v_rows integer;
begin
  if p_restore then
    -- Explicit undo of a deletion: save and clear the mark
    insert into public.trades as t (id, user_id, data, img_url, created_at, deleted_at)
    values (p_id, p_user_id, p_data, p_img_url, now(), null)
    on conflict (id, user_id) do update
      set data = excluded.data, img_url = excluded.img_url,
          created_at = excluded.created_at, deleted_at = null;
    return 'saved';
  end if;

  -- Normal save: the conflict update only happens while the row is not deleted.
  -- Check and write are one statement, so a late save cannot slip past a delete.
  insert into public.trades as t (id, user_id, data, img_url, created_at)
  values (p_id, p_user_id, p_data, p_img_url, now())
  on conflict (id, user_id) do update
    set data = excluded.data, img_url = excluded.img_url, created_at = excluded.created_at
    where t.deleted_at is null;
  get diagnostics v_rows = row_count;
  return case when v_rows > 0 then 'saved' else 'deleted' end;
end;
$$;

create or replace function public.mj_delete_trade(
  p_id      public.trades.id%type,
  p_user_id public.trades.user_id%type
) returns text
language plpgsql
set search_path = public
as $$
declare
  v_marker public.trades.data%type := jsonb_build_object('id', p_id, 'deleted', true);
begin
  -- Keep a content-free marker so a late save cannot bring the trade back
  insert into public.trades as t (id, user_id, data, img_url, created_at, deleted_at)
  values (p_id, p_user_id, v_marker, null, now(), now())
  on conflict (id, user_id) do update
    set data = excluded.data, img_url = null,
        deleted_at = coalesce(t.deleted_at, excluded.deleted_at);
  return 'deleted';
end;
$$;

-- Only the server's service key may call these (not the public anon key)
revoke all on function public.mj_save_trade   from public;
revoke all on function public.mj_delete_trade from public;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on function public.mj_save_trade from anon';
    execute 'revoke all on function public.mj_delete_trade from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke all on function public.mj_save_trade from authenticated';
    execute 'revoke all on function public.mj_delete_trade from authenticated';
  end if;
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    execute 'grant execute on function public.mj_save_trade to service_role';
    execute 'grant execute on function public.mj_delete_trade to service_role';
  end if;
end;
$$;

commit;

-- ── Rollback (only if needed; run the server's old version or restart it after) ──
-- begin;
-- drop function if exists public.mj_save_trade;
-- drop function if exists public.mj_delete_trade;
-- delete from public.trades where deleted_at is not null;   -- removes the content-free deletion markers
-- alter table public.trades drop column if exists deleted_at;
-- commit;
