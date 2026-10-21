/*
 * SQL check of db/migrations/2026-10-21-trade-deletion-guard.sql on a real
 * PostgreSQL engine (PGlite, PostgreSQL compiled to WASM). Made-up schema and
 * data only; nothing here talks to Supabase.
 *
 * Run:  node tests/deletion-guard.sql.test.cjs <path to @electric-sql/pglite>
 * (PGlite is not a project dependency; point it at any local install.)
 *
 * Limits: PGlite has a single connection, so this proves the logic,
 * permissions, re-runs and rollback — not races between parallel connections.
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const pglitePath = process.argv[2];
if (!pglitePath) { console.error('usage: node tests/deletion-guard.sql.test.cjs <pglite package dir>'); process.exit(2); }
const { PGlite } = require(path.join(pglitePath, 'dist', 'index.cjs'));
const MIGRATION = fs.readFileSync(path.join(__dirname, '..', 'db', 'migrations', '2026-10-21-trade-deletion-guard.sql'), 'utf8');
// The commented rollback block: from "-- begin;" to "-- commit;" after the Rollback heading
const rbLines = MIGRATION.split('-- ── Rollback')[1].split('\n');
const rbStart = rbLines.findIndex(l => l.trim() === '-- begin;');
const rbEnd = rbLines.findIndex((l, i) => i > rbStart && l.trim() === '-- commit;');
const ROLLBACK = rbLines.slice(rbStart, rbEnd + 1).map(l => l.replace(/^-- ?/, '')).join('\n');

// The first version of this migration (commit 4839fa9) — to prove an upgrade replaces it
const OLD_V1 = `
alter table public.trades add column if not exists deleted_at timestamptz;
create or replace function public.mj_save_trade(p_id public.trades.id%type, p_user_id public.trades.user_id%type,
  p_data public.trades.data%type, p_img_url public.trades.img_url%type, p_restore boolean default false)
returns text language plpgsql as $$ begin return 'old'; end $$;
create or replace function public.mj_delete_trade(p_id public.trades.id%type, p_user_id public.trades.user_id%type)
returns text language plpgsql as $$ begin return 'old'; end $$;`;

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });

async function scenario(idType, withOldV1) {
  const db = new PGlite();
  const label = `[id ${idType}${withOldV1 ? ', upgrade from v1' : ''}]`;
  await db.exec(`
    create role anon; create role authenticated; create role service_role;
    create table public.trades (id ${idType} not null, user_id bigint not null, data jsonb, img_url text,
                                created_at timestamptz, primary key (id, user_id));
    insert into public.trades values ('101', 7, '{"id":"101","pnl":"10"}', 'https://img/101.jpg', now());`);
  if (withOldV1) await db.exec(OLD_V1);

  await db.exec(MIGRATION);
  await db.exec(MIGRATION);                                              // re-run is safe
  check(`${label} migration runs twice`, true);
  const one = async (sql, params) => (await db.query(sql, params)).rows[0];
  const save = (id, uid, data, gen = null) => one(`select public.mj_save_trade($1,$2,$3::jsonb,null,$4) as r`, [id, uid, JSON.stringify(data), gen]).then(x => x.r);
  const del = (id, uid) => one(`select public.mj_delete_trade($1,$2) as g`, [id, uid]).then(x => Number(x.g));
  const row = (id, uid) => one(`select data, img_url, deleted_at, deleted_gen from public.trades where id=$1 and user_id=$2`, [id, uid]);

  const fnCount = await one(`select count(*)::int n from pg_proc where proname in ('mj_save_trade','mj_delete_trade','mj_guard_selftest')`);
  check(`${label} exactly one version of each function`, fnCount.n === 3, fnCount);
  check(`${label} existing row untouched`, (await row('101', 7)).data.pnl === '10');

  check(`${label} create`, await save('201', 7, { pnl: '1' }) === 'saved');
  check(`${label} edit`, await save('201', 7, { pnl: '2' }) === 'saved' && (await row('201', 7)).data.pnl === '2');
  const g1 = await del('201', 7);
  const r1 = await row('201', 7);
  check(`${label} delete wipes content, keeps marker`, g1 === 1 && r1.deleted_at && r1.data.pnl === undefined && r1.img_url === null, r1);
  check(`${label} late save after delete is refused`, await save('201', 7, { pnl: '3' }) === 'deleted' && (await row('201', 7)).data.pnl === undefined);
  check(`${label} late save also refused for a deleted image row`, await (async () => { await del('101', 7); return (await save('101', 7, { pnl: '99' })) === 'deleted' && (await row('101', 7)).img_url === null; })());

  const g2 = await del('201', 7);
  check(`${label} every deletion gets a new number`, g2 === g1 + 1, { g1, g2 });
  check(`${label} old undo cannot cancel a newer deletion`, await save('201', 7, { pnl: 'old-undo' }, g1) === 'deleted' && (await row('201', 7)).deleted_at !== null);
  check(`${label} undo of the latest deletion restores`, await save('201', 7, { pnl: 'undo' }, g2) === 'saved' && (await row('201', 7)).deleted_at === null && (await row('201', 7)).data.pnl === 'undo');
  check(`${label} restored trade saves normally`, await save('201', 7, { pnl: 'after' }) === 'saved' && (await row('201', 7)).data.pnl === 'after');
  check(`${label} undo number on an active row is just a save`, await save('201', 7, { pnl: 'x' }, 999) === 'saved');

  const gNew = await del('301', 7);                                   // deletion before the save ever arrived
  check(`${label} delete of a trade the server never had`, gNew === 1 && await save('301', 7, { pnl: 'late' }) === 'deleted');

  await del('401', 7);
  check(`${label} same id of another owner unaffected`, await save('401', 8, { pnl: 'B' }) === 'saved' && (await row('401', 8)).deleted_at === null);

  const before = await one(`select count(*)::int n from public.trades`);
  const st = (await one(`select public.mj_guard_selftest() as s`)).s;
  const after = await one(`select count(*)::int n from public.trades`);
  check(`${label} selftest reports ok and leaves no rows`, st.ok === true && before.n === after.n, { st, before, after });

  const priv = await db.query(`select r.rolname, f.proname, has_function_privilege(r.rolname, f.oid, 'execute') ok
    from pg_proc f cross join pg_roles r
    where f.proname in ('mj_save_trade','mj_delete_trade','mj_guard_selftest') and r.rolname in ('anon','authenticated','service_role')`);
  const bad = priv.rows.filter(x => (x.rolname === 'service_role') !== x.ok);
  check(`${label} only service_role may execute`, bad.length === 0 && priv.rows.length === 9, bad);

  await db.exec(ROLLBACK);
  const cols = await db.query(`select column_name from information_schema.columns where table_name='trades' and column_name like 'deleted%'`);
  const fns = await one(`select count(*)::int n from pg_proc where proname like 'mj\\_%'`);
  const active = await one(`select count(*)::int n from public.trades`);
  check(`${label} rollback removes guard and markers, keeps active rows`, cols.rows.length === 0 && fns.n === 0 && active.n === 2, { cols: cols.rows, fns, active });
  await db.close();
}

(async () => {
  await scenario('text', false);
  await scenario('bigint', false);
  await scenario('text', true);
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR', e); process.exit(1); });
