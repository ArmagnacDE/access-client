// Sperr-Label für Sicherheitsmails einrichten (src/gmail-setup.js, S112 „Ein Mail-Weg für Sessions und Agenten“, Board
// A694 a): Label und zwei Filter je Postfach, Dry-Run listet nur, Live legt nur Fehlendes an, nie löschen, nie senden.
// Ohne Netz: Gmail ist eine Attrappe.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SECURITY_FILTERS, planSecurityLabel, applySecurityLabel } from '../src/gmail-setup.js';

const BOX = 'hello@example.org';
function gmail({ labels = [{ id: 'INBOX', name: 'INBOX' }], filters = [] } = {}) {
  const log = [];
  const st = { labels: [...labels], filters: [...filters] };
  const f = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? 'GET';
    log.push({ method, url: String(url), path: decodeURIComponent(u.pathname), body: init.body ? JSON.parse(init.body) : null });
    const ok = (b, s = 200) => ({ ok: s < 400, status: s, json: async () => b });
    const p = decodeURIComponent(u.pathname).replace(`/gmail/v1/users/${BOX}/`, '');
    if (method === 'GET' && p === 'labels') return ok({ labels: st.labels });
    // echtes Gmail: ohne Filter ein leerer Antwortkörper (Dry-Run 24.11. gegen sascha@)
    if (method === 'GET' && p === 'settings/filters') return st.filters.length ? ok({ filter: st.filters }) : { ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected end of JSON input'); }, text: async () => '' };
    if (method === 'POST' && p === 'labels') { const l = { id: `Label_${st.labels.length}`, name: JSON.parse(init.body).name }; st.labels.push(l); return ok(l); }
    if (method === 'POST' && p === 'settings/filters') { const x = { id: `F${st.filters.length}`, ...JSON.parse(init.body) }; st.filters.push(x); return ok(x); }
    return ok({ error: { message: 'nicht erlaubt' } }, 405);
  };
  f.log = log; f.st = st;
  return f;
}
const T = { labelsToken: 'TL', filtersToken: 'TF' };

test('Filter: Betreff-Liste auf zwei Filter verteilt (S137) und reine Sicherheits-Absender', () => {
  assert.deepEqual(SECURITY_FILTERS.map((f) => f.name), ['filter-betreff', 'filter-betreff-2', 'filter-absender']);
  assert.match(SECURITY_FILTERS[0].criteria.query, /^subject:\("password reset" OR .*"alerte de sécurité"\)$/);
  assert.equal(SECURITY_FILTERS[2].criteria.from, 'accounts.google.com OR account-security-noreply@accountprotection.microsoft.com OR appleid@id.apple.com OR security@facebookmail.com');
});

test('Dry-Run: listet Fehlendes, schreibt nichts', async () => {
  const f = gmail();
  const p = await planSecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual({ label: p.labelId, fehlt: p.missing.map((x) => x.name) }, { label: null, fehlt: ['label', 'filter-betreff', 'filter-betreff-2', 'filter-absender'] });
  assert.ok(f.log.every((c) => c.method === 'GET'));
});

test('Live: legt Label und alle Filter an; zweiter Lauf legt nichts mehr an (idempotent)', async () => {
  const f = gmail();
  const r = await applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual(r.created.map((x) => x.name), ['label', 'filter-betreff', 'filter-betreff-2', 'filter-absender']);
  const posts = f.log.filter((c) => c.method !== 'GET');
  assert.deepEqual(posts.map((c) => [c.method, c.path.split('/').slice(5).join('/')]), [['POST', 'labels'], ['POST', 'settings/filters'], ['POST', 'settings/filters'], ['POST', 'settings/filters']]);
  assert.equal(posts[0].body.name, 'security-no-read');
  for (const c of posts.slice(1)) assert.deepEqual(c.body.action, { addLabelIds: [f.st.labels.at(-1).id] }, 'nur Label anwenden, kein Archivieren, kein Weiterleiten');
  const n = f.log.length;
  const r2 = await applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual(r2.created, []);
  assert.ok(f.log.slice(n).every((c) => c.method === 'GET'));
});

test('vorhandenes Label (andere Schreibweise) wird genutzt, nicht doppelt angelegt', async () => {
  const f = gmail({ labels: [{ id: 'Label_9', name: 'Security No Read' }] });
  const r = await applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual(r.created.map((x) => x.name), ['filter-betreff', 'filter-betreff-2', 'filter-absender']);
  assert.ok(f.log.filter((c) => c.method === 'POST').every((c) => c.body.action?.addLabelIds?.[0] === 'Label_9'));
});

test('nur zwei schreibende Endpunkte, nie DELETE, nie ein Versand- oder Weiterleitungs-Pfad', async () => {
  const f = gmail();
  await applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  for (const c of f.log) {
    assert.ok(['GET', 'POST'].includes(c.method), c.method);
    assert.doesNotMatch(c.url, /send|forwarding|delegates|imap|pop|vacation/i);
  }
  await assert.rejects(planSecurityLabel({ ...T, mailbox: 'x/../send', label: 'security-no-read', fetchImpl: f }), /Postfach|Versand/);
});

test('Codex S112 #2: vorhandener Filter mit zusätzlichen Kriterien (z. B. to) zählt nicht als Schutz', async () => {
  const f = gmail({ labels: [{ id: 'Label_9', name: 'security-no-read' }],
    filters: SECURITY_FILTERS.map((x, i) => ({ id: `F${i}`, criteria: { ...x.criteria, to: 'nur@example.org' }, action: { addLabelIds: ['Label_9'] } })) });
  const p = await planSecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual(p.missing.map((x) => x.name), ['filter-betreff', 'filter-betreff-2', 'filter-absender']);
});

test('Codex S112 #3: jede Anlage wird sofort gemeldet (Teilfehler verliert keine IDs)', async () => {
  const f = gmail();
  const inner = f;
  let n = 0;
  const brichtAb = async (url, init = {}) => { if ((init.method ?? 'GET') === 'POST' && ++n === 3) return { ok: false, status: 500, json: async () => ({}) }; return inner(url, init); };
  const gemeldet = [];
  await assert.rejects(applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: brichtAb, onCreated: (c) => gemeldet.push(c.name) }), /API 500/);
  assert.deepEqual(gemeldet, ['label', 'filter-betreff']);
});

test('reviewer S112 N5: security-label.mjs mit --apply und --dry-run bricht ab, bevor etwas geladen wird', async () => {
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync(process.execPath, [new URL('../scripts/security-label.mjs', import.meta.url).pathname, '--apply', '--dry-run'], { env: { ...process.env, ACCESS_READ_CONFIG: '/nicht/da.json' }, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--apply und --dry-run/);
});
