/*
 * SQL check of db/migrations/2026-10-28-strategy-docs.sql on a real
 * PostgreSQL engine (PGlite, PostgreSQL compiled to WASM). Made-up data only;
 * nothing here talks to Supabase.
 *
 * Run:  node tests/strategy-docs.sql.test.cjs <path to @electric-sql/pglite>
 * (PGlite is not a project dependency; point it at any local install.)
 *
 * Limits: PGlite has one connection, so this proves the logic, permissions,
 * re-runs and rollback — not races between parallel connections.
 */
const fs = require('fs');
const path = require('path');

const pglitePath = process.argv[2];
if (!pglitePath) { console.error('usage: node tests/strategy-docs.sql.test.cjs <pglite package dir>'); process.exit(2); }
const { PGlite } = require(path.join(pglitePath, 'dist', 'index.cjs'));
const MIGRATION = fs.readFileSync(path.join(__dirname, '..', 'db', 'migrations', '2026-10-28-strategy-docs.sql'), 'utf8');
const rbLines = MIGRATION.split('-- ── Rollback')[1].split('\n');
const rbStart = rbLines.findIndex(l => l.trim() === '-- begin;');
const rbEnd = rbLines.findIndex((l, i) => i > rbStart && l.trim() === '-- commit;');
const ROLLBACK = rbLines.slice(rbStart, rbEnd + 1).map(l => l.replace(/^-- ?/, '')).join('\n');

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });

(async () => {
  const db = new PGlite();
  // as in Supabase: the service key's role bypasses RLS, anon and authenticated do not
  await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;`);
  await db.exec(MIGRATION);
  await db.exec(MIGRATION);
  check('migration runs twice', true);

  const save = async (id, user, kind, data, v) =>
    (await db.query('select public.mj_save_doc($1,$2,$3,$4::jsonb,$5) as r', [id, user, kind, JSON.stringify(data), v])).rows[0].r;
  const del = async (id, user, kind, v) =>
    (await db.query('select public.mj_delete_doc($1,$2,$3,$4) as r', [id, user, kind, v])).rows[0].r;
  const row = async (id, user) =>
    (await db.query('select kind, data, v, deleted_at from public.strategy_docs where id=$1 and user_id=$2', [id, user])).rows[0];
  const throws = async sql => { try { await db.query(sql); return false; } catch (e) { return true; } };

  // strategy: insert, retry of the same version, an older version, a newer version
  check('new strategy → saved', await save('str_1', 7, 'strategy', { name: 'A' }, 100) === 'saved');
  check('same version again → same (idempotent retry)', await save('str_1', 7, 'strategy', { name: 'A' }, 100) === 'same');
  check('same version, other data → collision, not same', await save('str_1', 7, 'strategy', { name: 'B from another tab' }, 100) === 'collision');
  check('a collision does not overwrite', (await row('str_1', 7)).data.name === 'A');
  check('retry with the keys in another order → same', await save('str_k', 77, 'strategy', { name: 'X', b: 1 }, 5) === 'saved'
    && await save('str_k', 77, 'strategy', { b: 1, name: 'X' }, 5) === 'same');
  check('newer version → saved', await save('str_1', 7, 'strategy', { name: 'B' }, 200) === 'saved');
  check('older version arriving late → stale', await save('str_1', 7, 'strategy', { name: 'OLD' }, 150) === 'stale');
  let r = await row('str_1', 7);
  check('late older version did not overwrite', r.data.name === 'B' && Number(r.v) === 200, r);
  check('kind of a row can not change', await save('str_1', 7, 'note', { text: 'x' }, 300) === 'conflict');

  // accounts are separate: the same id in another account is another document
  check('same id, other account → its own row', await save('str_1', 8, 'strategy', { name: 'Other' }, 50) === 'saved');
  check('other account did not touch account 7', (await row('str_1', 7)).data.name === 'B');

  // revision: content is frozen, the check notes may be added later
  const content = { name: 'B', sections: [{ name: 'Вход', rules: ['BOS M5'] }], checklist: [] };
  check('revision saved', await save('rev_1', 7, 'revision', { strategyId: 'str_1', content, results: '' }, 10) === 'saved');
  check('revision content can not change', await save('rev_1', 7, 'revision', { strategyId: 'str_1', content: { ...content, name: 'C' }, results: '' }, 11) === 'immutable');
  check('revision check notes can be added', await save('rev_1', 7, 'revision', { strategyId: 'str_1', content, results: 'проверено на 20 сделках' }, 12) === 'saved');
  r = await row('rev_1', 7);
  check('revision keeps its content after the notes', r.data.content.name === 'B' && r.data.results === 'проверено на 20 сделках', r);

  // deletions: notes and hypotheses only; a late save never brings them back
  check('note saved', await save('note_1', 7, 'note', { text: 'наблюдение' }, 5) === 'saved');
  check('note deleted', await del('note_1', 7, 'note', 6) === 'deleted');
  r = await row('note_1', 7);
  check('deleted note: content wiped, mark kept', r.deleted_at && JSON.stringify(r.data) === '{}', r);
  check('late save of a deleted note → deleted', await save('note_1', 7, 'note', { text: 'наблюдение' }, 7) === 'deleted');
  check('deleting again → deleted', await del('note_1', 7, 'note', 8) === 'deleted');
  check('delete before the first save → mark', await del('hyp_9', 7, 'hypothesis', 3) === 'deleted');
  check('first save arriving after its delete → deleted', await save('hyp_9', 7, 'hypothesis', { title: 'x' }, 2) === 'deleted');
  check('an older delete than the last edit → stale', (await save('hyp_2', 7, 'hypothesis', { title: 'y' }, 50), await del('hyp_2', 7, 'hypothesis', 40)) === 'stale');
  check('strategy can not be deleted', await del('str_1', 7, 'strategy', 999) === 'refused');
  check('revision can not be deleted', await del('rev_1', 7, 'revision', 999) === 'refused');
  check('week note can not be deleted', await del('wk:str_1:2026-10-26', 7, 'week', 1) === 'refused');
  check('refused delete left the revision', !(await row('rev_1', 7)).deleted_at);

  // bad input
  check('empty id refused', await throws(`select public.mj_save_doc('', 7, 'note', '{}'::jsonb, 1)`));
  check('long id refused', await throws(`select public.mj_save_doc('${'x'.repeat(129)}', 7, 'note', '{}'::jsonb, 1)`));
  check('control character in id refused', await throws(`select public.mj_save_doc(E'a\\nb', 7, 'note', '{}'::jsonb, 1)`));
  check('unknown kind refused', await throws(`select public.mj_save_doc('a', 7, 'trade', '{}'::jsonb, 1)`));
  check('version 0 refused', await throws(`select public.mj_save_doc('a', 7, 'note', '{}'::jsonb, 0)`));
  check('array data refused', await throws(`select public.mj_save_doc('a', 7, 'note', '[]'::jsonb, 1)`));
  check('table check: unknown kind refused', await throws(`insert into public.strategy_docs (id,user_id,kind) values ('z',7,'trade')`));

  // permissions: only service_role
  await db.exec('set role anon');
  check('anon can not read the table', await throws('select * from public.strategy_docs'));
  check('anon can not call mj_save_doc', await throws(`select public.mj_save_doc('a', 7, 'note', '{}'::jsonb, 1)`));
  await db.exec('reset role; set role authenticated');
  check('authenticated can not read the table', await throws('select * from public.strategy_docs'));
  check('authenticated can not call mj_delete_doc', await throws(`select public.mj_delete_doc('a', 7, 'note', 1)`));
  await db.exec('reset role; set role service_role');
  check('service_role reads the table', !(await throws('select count(*) from public.strategy_docs')));
  check('service_role calls mj_save_doc', await save('svc_1', 9, 'week', { worked: 'x' }, 1) === 'saved');
  await db.exec('reset role');

  // rollback
  await db.exec(ROLLBACK);
  check('rollback removes the table', !(await throws('select 1')) && await throws('select * from public.strategy_docs'));
  check('rollback removes the functions', await throws(`select public.mj_save_doc('a', 7, 'note', '{}'::jsonb, 1)`));
  await db.exec(MIGRATION);
  check('migration runs again after rollback', await save('again', 7, 'note', { text: 'ok' }, 1) === 'saved');

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
