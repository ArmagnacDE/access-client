// S137 (Mail-Wächter-Job live): alte Betreff-Filter früherer Listen entfernen (scripts/security-label.mjs --remove-old),
// nur genau die Filter aus der Stand-Datei, nur wenn sie unverändert sind und die neuen Filter schon stehen; jede
// Löschung vorher gesichert, --restore legt sie wieder an. Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SECURITY_FILTERS } from '../src/gmail-setup.js';
import { oldFilterCandidates, planFilterCleanup, removeOldFilters, restoreFilters } from '../src/gmail-filter-cleanup.js';

const BOX = 'hello@example.org';
const L = 'Label_1';
const alt = (id, phrasen) => ({ id, criteria: { query: `subject:(${phrasen.map((p) => `"${p}"`).join(' OR ')})` }, action: { addLabelIds: [L] } });
const ALT = [alt('A1', ['password reset', 'Ihr Code lautet']), alt('A2', ['password reset', 'two-step', 'Ihr Code lautet'])];
const NEU = SECURITY_FILTERS.map((s, i) => ({ id: `N${i}`, criteria: s.criteria, action: { addLabelIds: [L] } }));
const FREMD = [{ id: 'X1', criteria: { from: 'shop@example.com' }, action: { addLabelIds: ['Label_7'], removeLabelIds: ['INBOX'] } },
  { id: 'X2', criteria: { query: 'subject:("password reset")' }, action: { addLabelIds: [L], forward: 'x@example.com' } }];
const STAND = { postfaecher: [{ mailbox: BOX, before: { filters: [...ALT, ...FREMD] } }] };

function gmail(filters) {
  const st = { filters: filters.map((f) => structuredClone(f)) };
  const log = [];
  const f = async (url, init = {}) => {
    const method = init.method ?? 'GET';
    const p = decodeURIComponent(new URL(url).pathname).replace(`/gmail/v1/users/${BOX}/`, '');
    log.push({ method, p });
    const ok = (b, s = 200) => ({ ok: s < 400, status: s, text: async () => (b == null ? '' : JSON.stringify(b)) });
    if (method === 'GET' && p === 'settings/filters') return ok(st.filters.length ? { filter: st.filters } : null);
    const m = /^settings\/filters\/([\w-]+)$/.exec(p);
    if (method === 'DELETE' && m) { st.filters = st.filters.filter((x) => x.id !== m[1]); return ok(null, 204); }
    if (method === 'POST' && p === 'settings/filters') { const x = { id: `R${st.filters.length}`, ...JSON.parse(init.body) }; st.filters.push(x); return ok(x); }
    return ok({ error: { message: 'nicht erlaubt' } }, 405);
  };
  f.st = st; f.log = log;
  return f;
}

test('Kandidaten aus der Stand-Datei: nur reine Betreff-Sperrfilter der alten Liste, nie fremde, nie die aktuellen', () => {
  const k = oldFilterCandidates({ ...STAND.postfaecher[0], before: { filters: [...ALT, ...FREMD, ...NEU] } });
  assert.deepEqual(k.map((x) => x.id), ['A1', 'A2']);
});

test('Plan: löscht nur, wenn die neuen Filter stehen und der alte unverändert ist; nur GET', async () => {
  const f = gmail([...ALT, ...NEU, ...FREMD]);
  const p = await planFilterCleanup({ token: 'T', mailbox: BOX, candidates: oldFilterCandidates(STAND.postfaecher[0]), fetchImpl: f });
  assert.deepEqual(p.delete.map((x) => x.id), ['A1', 'A2']);
  assert.ok(f.log.every((c) => c.method === 'GET'));
  const ohneNeu = await planFilterCleanup({ token: 'T', mailbox: BOX, candidates: oldFilterCandidates(STAND.postfaecher[0]), fetchImpl: gmail([...ALT, NEU[0]]) });
  assert.deepEqual(ohneNeu.delete, []);
  assert.match(ohneNeu.blocked, /neue Filter fehlen/);
  const geaendert = await planFilterCleanup({ token: 'T', mailbox: BOX, candidates: oldFilterCandidates(STAND.postfaecher[0]),
    fetchImpl: gmail([{ ...ALT[0], action: { addLabelIds: [L], forward: 'x@example.com' } }, ALT[1], ...NEU]) });
  assert.deepEqual(geaendert.delete.map((x) => x.id), ['A2']);
  assert.deepEqual(geaendert.changed, ['A1']);
  const weg = await planFilterCleanup({ token: 'T', mailbox: BOX, candidates: oldFilterCandidates(STAND.postfaecher[0]), fetchImpl: gmail([ALT[1], ...NEU]) });
  assert.deepEqual(weg.gone, ['A1']);
});

test('Löschen: jede ID erst gesichert, dann DELETE genau auf settings/filters/<id>; neue und fremde bleiben', async () => {
  const f = gmail([...ALT, ...NEU, ...FREMD]);
  const gesichert = [];
  const r = await removeOldFilters({ token: 'T', mailbox: BOX, candidates: oldFilterCandidates(STAND.postfaecher[0]), fetchImpl: f,
    onBackup: (x) => gesichert.push(x.id), onDeleted: (id) => assert.ok(gesichert.includes(id), 'vor dem Löschen gesichert') });
  assert.deepEqual(r.deleted, ['A1', 'A2']);
  assert.deepEqual(f.st.filters.map((x) => x.id).sort(), [...NEU.map((x) => x.id), 'X1', 'X2'].sort());
  assert.deepEqual(f.log.filter((c) => c.method !== 'GET').map((c) => `${c.method} ${c.p}`), ['DELETE settings/filters/A1', 'DELETE settings/filters/A2']);
});

test('Restore: legt gesicherte Filter mit Kriterium und Aktion wieder an, doppelt nie', async () => {
  const f = gmail([...NEU]);
  const r = await restoreFilters({ token: 'T', mailbox: BOX, filters: ALT, fetchImpl: f });
  assert.equal(r.created.length, 2);
  const r2 = await restoreFilters({ token: 'T', mailbox: BOX, filters: ALT, fetchImpl: f });
  assert.equal(r2.created.length, 0);
  assert.deepEqual(f.st.filters.filter((x) => x.id.startsWith('R')).map((x) => x.criteria.query), ALT.map((x) => x.criteria.query));
});

test('ungültige IDs und fremde Pfade werden nie gelöscht', async () => {
  const f = gmail([...ALT, ...NEU]);
  await assert.rejects(removeOldFilters({ token: 'T', mailbox: BOX, candidates: [{ ...ALT[0], id: '../send' }], fetchImpl: f }), /ID/);
  assert.ok(f.log.every((c) => c.method === 'GET'));
});
