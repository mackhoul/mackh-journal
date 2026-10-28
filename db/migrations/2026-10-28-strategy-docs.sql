-- ═══════════════════════════════════════════════════════════════════════
--  MackH Journal — strategy documents
--
--  Why: the «Стратегии» section keeps a trader's own strategies in the
--  account, so they survive closing the app and signing in on another device.
--
--  What it does:
--   1. public.strategy_docs — one row per document of one account:
--        strategy   — the rules, checklist and conditions being edited
--        revision   — a frozen copy of a strategy that trades point to; its
--                     content never changes after it is written
--        note       — an observation, optionally about one trade
--        hypothesis — an idea under test with its status and results
--        week       — the end-of-week note of one strategy and one week
--      v is the client's version of the document (grows with every edit).
--   2. mj_save_doc()   — insert or update one document. An older or equal
--      version never overwrites a newer one ('stale' / 'same'; the same
--      version with other data is 'collision', the app sends it again with a
--      higher version), a deleted
--      document is never re-created ('deleted'), a revision's content can not
--      be changed ('immutable'), the kind of a row can not change ('conflict').
--   3. mj_delete_doc() — deletes a note or a hypothesis: its content is wiped,
--      the row stays as a deletion mark so a late save can not bring it back.
--      Strategies are archived, revisions and week notes are not deleted, so
--      trades never lose the rules they were recorded with.
--   4. Only the server (service_role) may read the table and call the functions.
--
--  How to run: on a TEST project first. Supabase → SQL Editor → paste this
--  file → Run. Safe to run again (idempotent). The server works without it:
--  it answers 503 and the app keeps strategies on the device until it exists.
-- ═══════════════════════════════════════════════════════════════════════

begin;

create table if not exists public.strategy_docs (
  id         text        not null,
  user_id    bigint      not null,
  kind       text        not null,
  data       jsonb       not null default '{}'::jsonb,
  v          bigint      not null default 0,
  deleted_at timestamptz,
  updated_at timestamptz not null default now(),
  constraint strategy_docs_pkey primary key (id, user_id),
  constraint strategy_docs_kind check (kind in ('strategy','revision','note','hypothesis','week')),
  constraint strategy_docs_id_len check (char_length(id) between 1 and 128)
);
create index if not exists strategy_docs_user_idx on public.strategy_docs (user_id);

-- RLS on, no policies: only the server's service key can read or write rows
alter table public.strategy_docs enable row level security;
revoke all on table public.strategy_docs from public, anon, authenticated;
grant select, insert, update, delete on table public.strategy_docs to service_role;

create or replace function public.mj_save_doc(p_id text, p_user_id bigint, p_kind text, p_data jsonb, p_v bigint)
returns text
language plpgsql
set search_path = public, pg_temp
as $$
declare
  cur public.strategy_docs%rowtype;
begin
  if p_id is null or char_length(p_id) not between 1 and 128 or p_id ~ '[[:cntrl:]]' then
    raise exception 'mj_save_doc: invalid id' using errcode = '22023';
  end if;
  if p_user_id is null then raise exception 'mj_save_doc: no user' using errcode = '22023'; end if;
  if p_kind is null or p_kind not in ('strategy','revision','note','hypothesis','week') then
    raise exception 'mj_save_doc: invalid kind' using errcode = '22023';
  end if;
  if p_v is null or p_v < 1 then raise exception 'mj_save_doc: invalid version' using errcode = '22023'; end if;
  if p_data is null or jsonb_typeof(p_data) <> 'object' then
    raise exception 'mj_save_doc: data must be an object' using errcode = '22023';
  end if;

  insert into public.strategy_docs (id, user_id, kind, data, v)
  values (p_id, p_user_id, p_kind, p_data, p_v)
  on conflict (id, user_id) do nothing;
  if found then return 'saved'; end if;

  select * into cur from public.strategy_docs where id = p_id and user_id = p_user_id for update;
  if cur.kind <> p_kind        then return 'conflict'; end if;
  if cur.deleted_at is not null then return 'deleted';  end if;
  -- the same number is a retry only if it carries the same document; another text with it is a collision
  if p_v = cur.v then
    if cur.data = p_data then return 'same'; end if;
    return 'collision';
  end if;
  if p_v < cur.v               then return 'stale';    end if;
  if p_kind = 'revision' and (cur.data -> 'content') is distinct from (p_data -> 'content') then
    return 'immutable';
  end if;

  update public.strategy_docs
     set data = p_data, v = p_v, updated_at = now()
   where id = p_id and user_id = p_user_id;
  return 'saved';
end;
$$;

create or replace function public.mj_delete_doc(p_id text, p_user_id bigint, p_kind text, p_v bigint)
returns text
language plpgsql
set search_path = public, pg_temp
as $$
declare
  cur public.strategy_docs%rowtype;
begin
  if p_id is null or char_length(p_id) not between 1 and 128 or p_id ~ '[[:cntrl:]]' then
    raise exception 'mj_delete_doc: invalid id' using errcode = '22023';
  end if;
  if p_user_id is null then raise exception 'mj_delete_doc: no user' using errcode = '22023'; end if;
  if p_v is null or p_v < 1 then raise exception 'mj_delete_doc: invalid version' using errcode = '22023'; end if;
  if p_kind is null or p_kind not in ('note','hypothesis') then return 'refused'; end if;

  select * into cur from public.strategy_docs where id = p_id and user_id = p_user_id for update;
  if not found then
    -- deleted before its first save reached the server: the mark still blocks a late save
    insert into public.strategy_docs (id, user_id, kind, data, v, deleted_at)
    values (p_id, p_user_id, p_kind, '{}'::jsonb, p_v, now())
    on conflict (id, user_id) do nothing;
    if found then return 'deleted'; end if;
    select * into cur from public.strategy_docs where id = p_id and user_id = p_user_id for update;
  end if;
  if cur.kind <> p_kind         then return 'conflict'; end if;
  if cur.deleted_at is not null then return 'deleted';  end if;
  if p_v < cur.v                then return 'stale';    end if;

  update public.strategy_docs
     set data = '{}'::jsonb, v = p_v, deleted_at = now(), updated_at = now()
   where id = p_id and user_id = p_user_id;
  return 'deleted';
end;
$$;

revoke all on function public.mj_save_doc(text, bigint, text, jsonb, bigint)   from public, anon, authenticated;
revoke all on function public.mj_delete_doc(text, bigint, text, bigint)        from public, anon, authenticated;
grant execute on function public.mj_save_doc(text, bigint, text, jsonb, bigint) to service_role;
grant execute on function public.mj_delete_doc(text, bigint, text, bigint)      to service_role;

commit;

-- ── Rollback (removes the strategy documents of every account) ──────────
-- begin;
-- drop function if exists public.mj_save_doc(text, bigint, text, jsonb, bigint);
-- drop function if exists public.mj_delete_doc(text, bigint, text, bigint);
-- drop table if exists public.strategy_docs;
-- commit;
