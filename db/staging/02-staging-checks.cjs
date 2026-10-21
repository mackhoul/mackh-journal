/*
 * Staging checks for the trade deletion guard against a REAL Supabase TEST
 * project, through the real server.js running locally.
 *
 * Needs: .env.staging (TEST project only: SUPABASE_URL, SUPABASE_ANON_KEY,
 * SUPABASE_SERVICE_ROLE_KEY, TEST_USER_A/B_EMAIL/PASSWORD), the migration
 * applied in that project, server.js running against it (default
 * http://127.0.0.1:3010) and optionally the CSV backup of trades for the
 * restore rehearsal:  node db/staging/02-staging-checks.cjs [server] [csv]
 *
 * Refuses to run if .env.staging points at the production project (compared
 * with the public /config of the production server). Never prints secrets.
 * Uses made-up trades only; test rows it creates are removed at the end.
 */
const fs = require('fs');
const path = require('path');

const SERVER = process.argv[2] || 'http://127.0.0.1:3010';
const CSV = process.argv[3] || null;
const ENV_FILE = path.join(__dirname, '..', '..', '.env.staging');

const env = {};
for (const line of fs.readFileSync(ENV_FILE, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/); if (m) env[m[1]] = m[2].trim();
}
const SB = env.SUPABASE_URL;
const svcH = { 'Content-Type': 'application/json', apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: 'Bearer ' + env.SUPABASE_SERVICE_ROLE_KEY };
const anonH = { 'Content-Type': 'application/json', apikey: env.SUPABASE_ANON_KEY, Authorization: 'Bearer ' + env.SUPABASE_ANON_KEY };

const results = [];
const check = (name, ok, detail) => { results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail).slice(0, 300) }); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const uid = () => String(Date.now()) + String(Math.floor(Math.random() * 900 + 100));

async function signIn(email, password) {
  const r = await fetch(`${SB}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: env.SUPABASE_ANON_KEY }, body: JSON.stringify({ email, password }) });
  const j = await r.json(); if (!j.access_token) throw new Error('sign-in failed for ' + email + ' (HTTP ' + r.status + ')');
  return j.access_token;
}
const api = async (tok, method, p, body) => {
  const r = await fetch(SERVER + p, { method, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
};
const rest = async (h, method, p, body, prefer) => {
  const r = await fetch(`${SB}/rest/v1/${p}`, { method, headers: { ...h, ...(prefer ? { Prefer: prefer } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = null; const t = await r.text(); try { j = t ? JSON.parse(t) : null; } catch { j = t; }
  return { status: r.status, body: j };
};
const row = async (id, userId) => (await rest(svcH, 'GET', `trades?id=eq.${encodeURIComponent(id)}&user_id=eq.${userId}&select=*`)).body[0] || null;
const has = async (tok, id) => ((await api(tok, 'GET', '/trades')).body || []).some(t => t.id === id);

(async () => {
  // 0. never production
  const cfg = await (await fetch('https://mackh-journal.onrender.com/config')).json();
  const prodRef = ((cfg.supabase_url || '').match(/^https:\/\/([a-z0-9]+)\.supabase\.co/) || [])[1];
  const ref = (new URL(SB).hostname.match(/^([a-z0-9]+)\.supabase\.co$/) || [])[1];
  if (!ref || !prodRef || ref === prodRef) throw new Error('STOP: not a known TEST project');
  check('target is the TEST project, not production', true);

  // 1. health: both fields, not just HTTP 200
  const h = await api(null, 'GET', '/health/db');
  check('health: deletion_guard true AND deletion_guard_selftest.ok true', h.status === 200 && h.body?.deletion_guard === true && h.body?.deletion_guard_selftest?.ok === true, h.body);

  const A = await signIn(env.TEST_USER_A_EMAIL, env.TEST_USER_A_PASSWORD);
  const B = await signIn(env.TEST_USER_B_EMAIL, env.TEST_USER_B_PASSWORD);
  check('no token → 401', (await api(null, 'GET', '/trades')).status === 401);
  await api(A, 'GET', '/trades'); await api(B, 'GET', '/trades');          // first call creates the account links
  const link = async email => (await rest(svcH, 'GET', `account_links?email=eq.${encodeURIComponent(email)}&select=user_id`)).body[0]?.user_id;
  const uA = await link(env.TEST_USER_A_EMAIL), uB = await link(env.TEST_USER_B_EMAIL);
  check('both test accounts linked to internal ids', !!uA && !!uB && uA !== uB);

  // 2. normal save / edit / delete / late save / undo through the real server
  const t1 = uid();
  let r = await api(A, 'POST', '/trades', { id: t1, pair: 'STG_EURUSD', pnl: '10' });
  check('save', r.status === 200 && r.body?.ok && !r.body?.skipped && await has(A, t1), r);
  await api(A, 'POST', '/trades', { id: t1, pair: 'STG_EURUSD', pnl: '20' });
  check('edit', (await row(t1, uA))?.data?.pnl === '20');
  r = await api(A, 'DELETE', `/trades/${t1}`);
  const g1 = r.body?.deletion;
  const r1 = await row(t1, uA);
  check('delete returns a deletion number, hides, wipes content', r.status === 200 && g1 === 1 && !(await has(A, t1)) && r1?.deleted_at && r1?.data?.pnl === undefined && r1?.img_url === null, { r, r1 });
  r = await api(A, 'POST', '/trades', { id: t1, pair: 'STG_EURUSD', pnl: 'late' });
  check('late save after delete → skipped, stays deleted', r.body?.skipped === 'deleted' && !(await has(A, t1)) && (await row(t1, uA))?.deleted_at, r);
  r = await api(A, 'POST', '/trades', { id: t1, pnl: 'old-client', __restore: true });
  check('old client flag __restore:true does not lift a deletion', r.body?.skipped === 'deleted' && !(await has(A, t1)), r);
  r = await api(A, 'POST', '/trades', { id: t1, pair: 'STG_EURUSD', pnl: '20', __restore: g1 });
  const r2 = await row(t1, uA);
  check('undo with the right deletion number restores', r.body?.ok && !r.body?.skipped && await has(A, t1) && r2?.deleted_at === null && r2?.data?.pnl === '20' && !('__restore' in (r2?.data || {})), { r, r2 });
  const g2 = (await api(A, 'DELETE', `/trades/${t1}`)).body?.deletion;
  r = await api(A, 'POST', '/trades', { id: t1, pnl: 'stale', __restore: g1 });
  check('old undo (number 1) cannot lift deletion number 2', g2 === 2 && r.body?.skipped === 'deleted' && !(await has(A, t1)), { g2, r });
  r = await api(A, 'POST', '/trades', { id: t1, pnl: 'ok', __restore: g2 });
  check('undo of the latest deletion works', r.body?.ok && !r.body?.skipped && await has(A, t1));

  // 3. ids, owners, public keys
  const imp = 'import.' + uid();
  await api(A, 'POST', '/trades', { id: imp, pnl: '1' });
  r = await api(A, 'DELETE', `/trades/${encodeURIComponent(imp)}`);
  check('non-numeric id can be saved and deleted', r.status === 200 && !(await has(A, imp)), r);
  const shared = uid();
  await api(A, 'POST', '/trades', { id: shared, owner: 'A', pnl: '1' });
  await api(B, 'POST', '/trades', { id: shared, owner: 'B', pnl: '2' });
  await api(B, 'DELETE', `/trades/${shared}`);
  check('same id: B deleting does not touch A', await has(A, shared) && !(await has(B, shared)) && !((await api(B, 'GET', '/trades')).body || []).some(t => t.owner === 'A'));
  const rpcAnon = await rest(anonH, 'POST', 'rpc/mj_save_trade', { p_id: 'x', p_user_id: uA, p_data: { hacked: true }, p_img_url: null });
  const rpcUser = await rest({ 'Content-Type': 'application/json', apikey: env.SUPABASE_ANON_KEY, Authorization: 'Bearer ' + A }, 'POST', 'rpc/mj_delete_trade', { p_id: t1, p_user_id: uA });
  const rpcSelf = await rest(anonH, 'POST', 'rpc/mj_guard_selftest', {});
  check('public anon key cannot call the guard functions', rpcAnon.status >= 400 && rpcSelf.status >= 400, { rpcAnon: rpcAnon.status, rpcSelf: rpcSelf.status });
  check('a signed-in user token cannot call them directly', rpcUser.status >= 400 && await has(A, t1), { rpcUser: rpcUser.status });
  const readAnon = await rest(anonH, 'GET', 'trades?select=id&limit=5');
  const readUser = await rest({ apikey: env.SUPABASE_ANON_KEY, Authorization: 'Bearer ' + A }, 'GET', 'trades?select=id&limit=5');
  check('RLS: public key and user token read no trade rows directly', Array.isArray(readAnon.body) && readAnon.body.length === 0 && Array.isArray(readUser.body) && readUser.body.length === 0, { readAnon, readUser });

  // 4. real concurrency through PostgREST
  let raceFails = [];
  for (let round = 0; round < 8; round++) {
    const x = uid();
    await api(A, 'POST', '/trades', { id: x, pnl: 'base' });
    const ops = [];
    const delAt = Math.floor(Math.random() * 10);
    for (let i = 0; i < 10; i++) {
      ops.push((async () => { await sleep(Math.random() * 40); return api(A, 'POST', '/trades', { id: x, pnl: 'p' + i }); })());
      if (i === delAt) ops.push((async () => { await sleep(Math.random() * 40); return api(A, 'DELETE', `/trades/${x}`); })());
    }
    const res = await Promise.all(ops);
    const rr = await row(x, uA);
    const ok = res.every(o => o.status === 200) && rr?.deleted_at && rr?.data?.pnl === undefined && !(await has(A, x));
    if (!ok) raceFails.push({ round, statuses: res.map(o => o.status), row: rr });
  }
  check('8 rounds: 10 parallel saves + 1 delete → always deleted, never re-created', raceFails.length === 0, raceFails);
  const y = uid();
  await api(A, 'POST', '/trades', { id: y, pnl: '1' });
  const dels = await Promise.all(Array.from({ length: 5 }, () => api(A, 'DELETE', `/trades/${y}`)));
  const gens = dels.map(d => d.body?.deletion).sort((a, b) => a - b);
  check('5 parallel deletes get distinct numbers 1..5', JSON.stringify(gens) === '[1,2,3,4,5]' && (await row(y, uA))?.deleted_gen === 5, gens);
  const z = uid();
  await api(A, 'POST', '/trades', { id: z, pnl: '1' });
  const gz = (await api(A, 'DELETE', `/trades/${z}`)).body?.deletion;
  const [undoRes, delRes] = await Promise.all([api(A, 'POST', '/trades', { id: z, pnl: 'undo', __restore: gz }), api(A, 'DELETE', `/trades/${z}`)]);
  check('undo racing a newer delete always ends deleted', !(await has(A, z)) && (await row(z, uA))?.deleted_at, { undoRes: undoRes.body, delRes: delRes.body });
  const many = Array.from({ length: 20 }, () => uid() + Math.floor(Math.random() * 1000));
  await Promise.all(many.map((id, i) => api(A, 'POST', '/trades', { id, pnl: String(i) })));
  const got = ((await api(A, 'GET', '/trades')).body || []).map(t => t.id);
  check('20 parallel saves of different trades all stored', many.every(id => got.includes(id)));

  // 5. health after all that
  const h2 = await api(null, 'GET', '/health/db');
  check('health still both true afterwards', h2.body?.deletion_guard === true && h2.body?.deletion_guard_selftest?.ok === true);

  // 6. restore rehearsal from the CSV backup (made before the migration)
  if (CSV) {
    const lines = fs.readFileSync(CSV, 'utf8').trim().split(/\r?\n/);
    const parse = l => { const out = []; let cur = '', q = false; for (let i = 0; i < l.length; i++) { const c = l[i]; if (q) { if (c === '"' && l[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; } else if (c === '"') q = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c; } out.push(cur); return out; };
    const head = parse(lines[0]);
    const rows = lines.slice(1).map(l => Object.fromEntries(parse(l).map((v, i) => [head[i], v === '' ? null : v])));
    const ids = [...new Set(rows.map(x => x.user_id))].join(',');
    const before = (await rest(svcH, 'GET', `trades?user_id=in.(${ids})&select=id`)).body.length;
    await rest(svcH, 'DELETE', `trades?user_id=in.(${ids})`);
    const gone = (await rest(svcH, 'GET', `trades?user_id=in.(${ids})&select=id`)).body.length;
    const ins = await rest(svcH, 'POST', 'trades', rows.map(x => ({ id: x.id, user_id: Number(x.user_id), data: JSON.parse(x.data), img_url: x.img_url, created_at: x.created_at })), 'return=minimal');
    const back = (await rest(svcH, 'GET', `trades?user_id=in.(${ids})&select=*&order=id,user_id`)).body;
    const same = rows.length === back.length && rows.every(x => back.some(b => b.id === x.id && String(b.user_id) === x.user_id && JSON.stringify(b.data) === JSON.stringify(JSON.parse(x.data)) && b.img_url === x.img_url && b.deleted_at === null && b.deleted_gen === 0));
    check(`restore from CSV: ${rows.length} rows deleted and restored identically`, before === rows.length && gone === 0 && ins.status < 300 && same, { before, gone, ins: ins.status, back: back.length });
  }

  // cleanup: rows created by the two test accounts
  await rest(svcH, 'DELETE', `trades?user_id=in.(${uA},${uB})`);

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
