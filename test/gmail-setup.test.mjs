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

test('zwei Filter wie in der Unraid-README: Betreff-Liste und reine Sicherheits-Absender', () => {
  assert.equal(SECURITY_FILTERS.length, 2);
  assert.match(SECURITY_FILTERS[0].criteria.query, /^subject:\("password reset" OR .*"Ihr Code lautet"\)$/);
  assert.equal(SECURITY_FILTERS[1].criteria.from, 'accounts.google.com OR account-security-noreply@accountprotection.microsoft.com OR appleid@id.apple.com OR security@facebookmail.com');
});

test('Dry-Run: listet Fehlendes, schreibt nichts', async () => {
  const f = gmail();
  const p = await planSecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual({ label: p.labelId, fehlt: p.missing.map((x) => x.name) }, { label: null, fehlt: ['label', 'filter-betreff', 'filter-absender'] });
  assert.ok(f.log.every((c) => c.method === 'GET'));
});

test('Live: legt Label und beide Filter an; zweiter Lauf legt nichts mehr an (idempotent)', async () => {
  const f = gmail();
  const r = await applySecurityLabel({ ...T, mailbox: BOX, label: 'security-no-read', fetchImpl: f });
  assert.deepEqual(r.created.map((x) => x.name), ['label', 'filter-betreff', 'filter-absender']);
  const posts = f.log.filter((c) => c.method !== 'GET');
  assert.deepEqual(posts.map((c) => [c.method, c.path.split('/').slice(5).join('/')]), [['POST', 'labels'], ['POST', 'settings/filters'], ['POST', 'settings/filters']]);
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
  assert.deepEqual(r.created.map((x) => x.name), ['filter-betreff', 'filter-absender']);
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
