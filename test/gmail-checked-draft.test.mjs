// createCheckedDraft: Entwurf nur nach Profil-Prüfung, nie gesendet, kein zweiter Versuch bei 5xx. Ohne Netz.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCheckedDraft } from '../src/gmail.js';

function fake({ profil = 'mail@example.org', draftStatus = 200, draftBody = { id: 'r-1', message: { id: 'm-1', threadId: 't-1' } }, wirft = false } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? 'GET', body: init.body });
    if (/\/profile$/.test(new URL(url).pathname)) return { ok: true, status: 200, json: async () => ({ emailAddress: profil }) };
    if (wirft) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
    return { ok: draftStatus < 400, status: draftStatus, json: async () => draftBody };
  };
  f.calls = calls;
  return f;
}
const ARG = { token: 'T', expectedMailbox: 'Mail@Example.org', to: 'kunde@example.com', subject: 'Re: Paket', html: '<p>Hallo</p>' };

test('Profil passt → genau ein POST drafts in genau diesem Postfach', async () => {
  const f = fake();
  const r = await createCheckedDraft({ ...ARG, reply: { inReplyTo: '<a@b.c>', threadId: 't-9' }, fetchImpl: f });
  assert.deepEqual(r, { draftId: 'r-1', messageId: 'm-1', threadId: 't-1', mailbox: 'mail@example.org' });
  assert.deepEqual(f.calls.map((c) => [c.method, new URL(c.url).pathname]), [
    ['GET', '/gmail/v1/users/mail%40example.org/profile'],
    ['POST', '/gmail/v1/users/mail%40example.org/drafts'],
  ]);
  const body = JSON.parse(f.calls[1].body);
  assert.equal(body.message.threadId, 't-9');
  assert.match(Buffer.from(body.message.raw, 'base64url').toString('utf8'), /In-Reply-To: <a@b\.c>/);
});

test('Profil passt nicht → nichts angelegt', async () => {
  const f = fake({ profil: 'owner@example.org' });
  await assert.rejects(createCheckedDraft({ ...ARG, fetchImpl: f }), /gehört zu owner@example\.org, erwartet mail@example\.org; nichts angelegt/);
  assert.deepEqual(f.calls.map((c) => c.method), ['GET'], 'nur das Profil gelesen');
});

test('5xx und Verbindungsabbruch beim Anlegen: kein zweiter Versuch, Hinweis „NICHT wiederholen“', async () => {
  for (const f of [fake({ draftStatus: 503, draftBody: {} }), fake({ wirft: true }), fake({ draftBody: {} })]) {
    await assert.rejects(createCheckedDraft({ ...ARG, fetchImpl: f }), /NICHT wiederholen/);
    assert.equal(f.calls.filter((c) => c.method === 'POST').length, 1, 'genau ein Versuch');
  }
  const f4 = fake({ draftStatus: 400, draftBody: { error: { message: 'Invalid To header' } } });
  await assert.rejects(createCheckedDraft({ ...ARG, fetchImpl: f4 }), /API 400: Invalid To header/);
});

test('Pflichtfelder: ohne volle Postfach-Adresse, Betreff oder Text nichts abgerufen', async () => {
  const f = fake();
  await assert.rejects(createCheckedDraft({ ...ARG, expectedMailbox: 'me', fetchImpl: f }), /expectedMailbox/);
  await assert.rejects(createCheckedDraft({ ...ARG, subject: '', fetchImpl: f }), /Pflicht/);
  assert.equal(f.calls.length, 0);
});

test('Zeilenumbruch in to, subject oder cc: nichts abgerufen, kein Entwurf (keine fremden Kopfzeilen)', async () => {
  for (const extra of [{ subject: 'Re: Anfrage\r\nBcc: fremd@example.net' }, { to: 'a@example.com\nBcc: x@example.net' }, { cc: ['ok@example.com', 'b@example.com\r\nX: y'] }]) {
    const f = fake();
    await assert.rejects(createCheckedDraft({ ...ARG, ...extra, fetchImpl: f }), /Zeilenumbruch/);
    assert.equal(f.calls.length, 0);
  }
});
