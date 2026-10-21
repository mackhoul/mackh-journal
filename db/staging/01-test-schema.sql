-- ═══════════════════════════════════════════════════════════════════════
--  ONLY for the TEST project (mackh-journal-test). Never run in production.
--
--  Recreates the structure of the production tables (read 2026-10-21 via a
--  read-only catalog query): same columns, types, defaults, keys, indexes,
--  foreign key, RLS enabled with no policies, and the same table grants.
--  No data.
--
--  Safety: if public.trades already exists (e.g. this is the production
--  project by mistake) the script stops and changes nothing.
-- ═══════════════════════════════════════════════════════════════════════

begin;

do $$
begin
  if to_regclass('public.trades') is not null then
    raise exception 'STOP: public.trades already exists — this is not an empty test project. Nothing was changed.';
  end if;
end;
$$;

create table public.trades (
  id         text   not null,
  user_id    bigint not null,
  data       jsonb,
  img_url    text,
  created_at timestamp without time zone default now(),
  constraint trades_pkey primary key (id, user_id)
);

create table public.users (
  user_id      bigint not null,
  base_capital numeric default 0,
  goals        jsonb,
  updated_at   timestamp without time zone default now(),
  constraint users_pkey primary key (user_id)
);

create table public.account_links (
  auth_id     uuid   not null,
  user_id     bigint not null,
  email       text,
  telegram_id bigint,
  created_at  timestamp with time zone default now(),
  constraint account_links_pkey primary key (auth_id),
  constraint account_links_auth_id_fkey foreign key (auth_id) references auth.users(id) on delete cascade
);
create index account_links_user_id_idx on public.account_links using btree (user_id);

create table public.subscriptions (
  user_id            bigint not null,
  stripe_customer_id text,
  stripe_sub_id      text,
  status             text,
  current_period_end timestamp with time zone,
  updated_at         timestamp with time zone default now(),
  constraint subscriptions_pkey primary key (user_id)
);
create index subscriptions_customer_idx on public.subscriptions using btree (stripe_customer_id);

-- RLS on, no policies: only the server's service key can read or write rows
alter table public.trades        enable row level security;
alter table public.users         enable row level security;
alter table public.account_links enable row level security;
alter table public.subscriptions enable row level security;

-- Same table grants as production
grant all on public.trades, public.users, public.account_links, public.subscriptions
  to anon, authenticated, service_role;

commit;
