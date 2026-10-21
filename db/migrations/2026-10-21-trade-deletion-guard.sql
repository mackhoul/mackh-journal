-- ═══════════════════════════════════════════════════════════════════════
--  MackH Journal — trade deletion guard
--
--  Why: a save that was sent before a delete (and arrived late, e.g. after
--  a client timeout) could re-create the deleted trade. With this migration
--  the database remembers deletions and refuses a late save atomically.
--
--  What it does:
--   1. trades.deleted_at  — when the trade was deleted (NULL = active).
--      trades.deleted_gen — number of the latest deletion of this row
--                           (grows by 1 with every deletion).
--   2. mj_save_trade()    — insert/update a trade unless it is deleted.
--      An explicit "Undo" passes p_restore_gen = the number of the deletion
--      it undoes; it only works while that is still the latest deletion, so
--      an old undo can never cancel a newer deletion.
--   3. mj_delete_trade()  — marks the trade deleted, wipes its content (data
--      and img_url; only id, owner and the marks stay) and returns the new
--      deletion number. Works even if the trade has not reached the server yet.
--   4. mj_guard_selftest() — runs the functions on a made-up trade inside a
--      sub-transaction, rolls everything back and returns the results, so the
--      server can prove the guard works without touching real rows.
--   5. Only the server (service_role) may call the functions.
--
--  How to run: Supabase → SQL Editor → paste this file → Run. Safe to run
--  again (idempotent). Read db/DEPLOY-trade-deletion-guard.md first.
-- ═══════════════════════════════════════════════════════════════════════

begin;

alter table public.trades add column if not exists deleted_at  timestamptz;
alter table public.trades add column if not exists deleted_gen bigint not null default 0;

-- Re-running replaces the functions (any earlier signature is dropped first)
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig
    from pg_proc p
    where p.pronamespace = 'public'::regnamespace
      and p.proname in ('mj_save_trade', 'mj_delete_trade', 'mj_guard_selftest')
  loop
    execute 'drop function ' || r.sig;
  end loop;
end;
$$;

create function public.mj_save_trade(
  p_id          public.trades.id%type,
  p_user_id     public.trades.user_id%type,
  p_data        public.trades.data%type,
  p_img_url     public.trades.img_url%type,
  p_restore_gen bigint default null
) returns text
language plpgsql
set search_path = public
as $$
declare
  v_rows integer;
begin
  -- One statement: the update only happens while the row is not deleted, or
  -- when this save is the undo of exactly the latest deletion. A late save
  -- or an outdated undo changes nothing and gets 'deleted' back.
  insert into public.trades as t (id, user_id, data, img_url, created_at)
  values (p_id, p_user_id, p_data, p_img_url, now())
  on conflict (id, user_id) do update
    set data = excluded.data, img_url = excluded.img_url,
        created_at = excluded.created_at, deleted_at = null
    where t.deleted_at is null
       or (p_restore_gen is not null and t.deleted_gen = p_restore_gen);
  get diagnostics v_rows = row_count;
  return case when v_rows > 0 then 'saved' else 'deleted' end;
end;
$$;

create function public.mj_delete_trade(
  p_id      public.trades.id%type,
  p_user_id public.trades.user_id%type
) returns bigint
language plpgsql
set search_path = public
as $$
declare
  v_marker public.trades.data%type := jsonb_build_object('id', p_id, 'deleted', true);
  v_gen    bigint;
begin
  -- Keep a content-free marker so a late save cannot bring the trade back;
  -- every deletion gets a new number
  insert into public.trades as t (id, user_id, data, img_url, created_at, deleted_at, deleted_gen)
  values (p_id, p_user_id, v_marker, null, now(), now(), 1)
  on conflict (id, user_id) do update
    set data = excluded.data, img_url = null,
        deleted_at = now(), deleted_gen = t.deleted_gen + 1
  returning deleted_gen into v_gen;
  return v_gen;
end;
$$;

create function public.mj_guard_selftest()
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  v     jsonb := '{}'::jsonb;
  -- A made-up row that cannot belong to anyone (negative id and owner)
  v_id  public.trades.id%type      := '-987654321';
  v_uid public.trades.user_id%type := '-987654321';
  g1 bigint; g2 bigint; r text; wiped boolean;
begin
  begin
    r  := public.mj_save_trade(v_id, v_uid, '{"pnl":"1"}', null, null);   v := v || jsonb_build_object('save', r);
    g1 := public.mj_delete_trade(v_id, v_uid);
    select (data::jsonb ->> 'pnl') is null and img_url is null and deleted_at is not null
      into wiped from public.trades where id = v_id and user_id = v_uid;          v := v || jsonb_build_object('wiped', wiped);
    r  := public.mj_save_trade(v_id, v_uid, '{"pnl":"2"}', null, null);   v := v || jsonb_build_object('late_save', r);
    g2 := public.mj_delete_trade(v_id, v_uid);
    r  := public.mj_save_trade(v_id, v_uid, '{"pnl":"3"}', null, g1);     v := v || jsonb_build_object('old_undo', r);
    r  := public.mj_save_trade(v_id, v_uid, '{"pnl":"4"}', null, g2);     v := v || jsonb_build_object('undo', r);
    v := v || jsonb_build_object('ok',
           v->>'save' = 'saved' and (v->>'wiped')::boolean and v->>'late_save' = 'deleted'
           and v->>'old_undo' = 'deleted' and v->>'undo' = 'saved' and g2 = g1 + 1);
    -- Undo every change made above
    raise exception using errcode = 'MJ001', message = v::text;
  exception when sqlstate 'MJ001' then
    return sqlerrm::jsonb;
  end;
end;
$$;

-- Only the server's service key may call these (not the public anon key)
revoke all on function public.mj_save_trade     from public;
revoke all on function public.mj_delete_trade   from public;
revoke all on function public.mj_guard_selftest from public;
do $$
declare f text;
begin
  foreach f in array array['mj_save_trade', 'mj_delete_trade', 'mj_guard_selftest'] loop
    if exists (select 1 from pg_roles where rolname = 'anon') then
      execute format('revoke all on function public.%I from anon', f);
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
      execute format('revoke all on function public.%I from authenticated', f);
    end if;
    if exists (select 1 from pg_roles where rolname = 'service_role') then
      execute format('grant execute on function public.%I to service_role', f);
    end if;
  end loop;
end;
$$;

commit;

-- ── Rollback (only if needed). Afterwards restart the server on Render so it
--    switches to the old mode at once. Content of trades deleted while the
--    guard was on is not brought back — it was wiped on deletion.
-- begin;
-- drop function if exists public.mj_save_trade;
-- drop function if exists public.mj_delete_trade;
-- drop function if exists public.mj_guard_selftest;
-- delete from public.trades where deleted_at is not null;   -- removes the content-free deletion markers
-- alter table public.trades drop column if exists deleted_gen;
-- alter table public.trades drop column if exists deleted_at;
-- commit;
