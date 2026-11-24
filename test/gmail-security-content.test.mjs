// Sicherheitsmails OHNE Label (älter als die Filter, S112 „Ein Mail-Weg für Sessions und Agenten“, Orchestrator 24.11.):
// Mit blockSecurityContent schließt der Wächter dieselben Merkmale aus wie die zwei Gmail-Filter (eine Liste,
// src/security-mail.js): Suche bekommt -subject:(…) und -from:(…), Mail/Verlauf/Anhang werden vor dem Inhalt an From
// und Subject geprüft. Ohne Netz.
import test from 'node:test';
import assert from 'node:assert/strict';
import { configureGmailGuard, gmailGet, getMessage } from '../src/gmail.js';
import { SECURITY_SUBJECTS, SECURITY_SENDERS, isSecurityMail, securityExclusionQuery } from '../src/security-mail.js';
import { SECURITY_FILTERS } from '../src/gmail-setup.js';

configureGmailGuard({ blockedLabel: 'agent-no-read', requireLabel: true, blockSecurityContent: true });

const MAILS = {
  aa01: { from: 'Google <no-reply@accounts.google.com>', subject: 'Sicherheitswarnung' },
  aa02: { from: 'Shop <info@shop.example>', subject: 'Dein Code lautet 123456' },
  aa03: { from: 'Kunde <k@kunde.example>', subject: 'Frage zur Lieferung' },
  aa04: { from: 'GitHub <noreply@github.com>', subject: '[GitHub] Please verify your device: verification code' },
};
function fake() {
  const log = [];
  const f = async (url) => {
    const u = new URL(url);
    log.push({ path: decodeURIComponent(u.pathname), q: Object.fromEntries(u.searchParams), all: [...u.searchParams] });
    const p = decodeURIComponent(u.pathname).split('/').slice(5).join('/');
    const ok = (b) => ({ ok: true, status: 200, json: async () => b });
    const msg = (id) => {
      const m = MAILS[id];
      const fmt = u.searchParams.get('format');
      const headers = fmt === 'minimal' ? undefined : [{ name: 'From', value: m.from }, { name: 'Subject', value: m.subject }];
      return { id, threadId: `t-${id}`, labelIds: ['INBOX'], payload: { headers, ...(fmt === 'full' ? { body: { data: 'SU5IQUxU' } } : {}) } };
    };
    if (p === 'labels') return ok({ labels: [{ id: 'INBOX', name: 'INBOX' }, { id: 'Label_S', name: 'agent-no-read' }] });
    if (p === 'messages') return ok({ messages: [] });
    let m = /^messages\/([^/]+)$/.exec(p);
    if (m) return ok(msg(m[1]));
    m = /^messages\/([^/]+)\/attachments\/.+$/.exec(p);
    if (m) return ok({ data: 'eA' });
    m = /^threads\/t-([^/]+)$/.exec(p);
    if (m) return ok({ id: `t-${m[1]}`, messages: [msg('aa03'), msg(m[1])] });
    return ok({});
  };
  f.log = log;
  return f;
}
const A = { token: 'T', mailbox: 'hello@example.org' };

test('eine Liste: Filter der Einrichtung und Wächter nutzen dieselben Betreffe und Absender', () => {
  assert.ok(SECURITY_SUBJECTS.includes('Dein Code lautet') && SECURITY_SUBJECTS.length === 26);
  assert.deepEqual(SECURITY_SENDERS, ['accounts.google.com', 'account-security-noreply@accountprotection.microsoft.com', 'appleid@id.apple.com', 'security@facebookmail.com']);
  assert.equal(SECURITY_FILTERS[0].criteria.query, `subject:(${SECURITY_SUBJECTS.map((s) => `"${s}"`).join(' OR ')})`);
  assert.equal(SECURITY_FILTERS[1].criteria.from, SECURITY_SENDERS.join(' OR '));
  assert.equal(securityExclusionQuery(), `-${SECURITY_FILTERS[0].criteria.query} -from:(${SECURITY_SENDERS.join(' OR ')})`);
});

test('isSecurityMail: Betreff (Groß/klein egal) oder Absender aus der Liste', () => {
  assert.equal(isSecurityMail(MAILS.aa01), true);
  assert.equal(isSecurityMail(MAILS.aa02), true);
  assert.equal(isSecurityMail({ from: 'x@y.example', subject: 'PASSWORT ZURÜCKSETZEN' }), true);
  assert.equal(isSecurityMail(MAILS.aa03), false);
});

test('Suche schließt Label UND die Filter-Merkmale aus', async () => {
  const f = fake();
  await gmailGet({ ...A, path: 'messages', params: { q: 'newer_than:7d' }, fetchImpl: f });
  const q = f.log.find((c) => c.path.endsWith('/messages')).q.q;
  assert.equal(q, `(newer_than:7d) -label:agent-no-read ${securityExclusionQuery()}`);
});

test('Mail, Verlauf und Anhang mit Sicherheits-Merkmal: gesperrt, Inhalt nie abgerufen', async () => {
  for (const id of ['aa01', 'aa02', 'aa04']) {
    const f = fake();
    await assert.rejects(getMessage({ ...A, id, format: 'full', fetchImpl: f }), /Sicherheitsmail/, id);
    assert.ok(!f.log.some((c) => c.q.format === 'full'), `${id}: Inhalt abgerufen`);
    const g = fake();
    await assert.rejects(gmailGet({ ...A, path: `threads/t-${id}`, params: { format: 'full' }, fetchImpl: g }), /Sicherheitsmail/);
    assert.ok(!g.log.some((c) => c.q.format === 'full'));
    const h = fake();
    await assert.rejects(gmailGet({ ...A, path: `messages/${id}/attachments/X1`, fetchImpl: h }), /Sicherheitsmail/);
    assert.ok(!h.log.some((c) => c.path.includes('/attachments/')));
  }
  const ok = fake();
  const m = await getMessage({ ...A, id: 'aa03', format: 'full', fetchImpl: ok });
  assert.equal(m.id, 'aa03');
});

test('reviewer S112 B1: wortweise wie Gmail (Bindestrich = Trenner, kein Treffer mitten im Wort)', () => {
  assert.equal(isSecurityMail({ from: 'a@b.example', subject: 'Your one time password' }), true);
  assert.equal(isSecurityMail({ from: 'a@b.example', subject: 'New sign in on Mac' }), true);
  assert.equal(isSecurityMail({ from: 'a@b.example', subject: 'Two-factor: neue Anmeldung' }), true);
  assert.equal(isSecurityMail({ from: 'a@b.example', subject: 'Ticket A2FA91 erledigt' }), false);
  assert.equal(isSecurityMail({ from: 'no-reply@accounts.google.com', subject: 'x' }), true);
});
