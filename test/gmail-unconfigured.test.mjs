// Ohne configureGmailGuard liest kein Inhaltspfad (fail-closed); Profil und Labels gehen, Versand bleibt gesperrt.
import test from 'node:test';
import assert from 'node:assert/strict';
import { gmailGet, getMessage, gmailPost, GmailSendBlockedError, SEND_BLOCKED_DEFAULT } from '../src/gmail.js';

test('unkonfiguriert: Suche, Mail, Verlauf werfen vor jedem Abruf; Profil geht', async () => {
  const log = [];
  const fetchImpl = async (url) => { log.push(url); return { ok: true, status: 200, json: async () => ({ emailAddress: 'x@example.org', messages: [] }) }; };
  for (const path of ['messages', 'messages/m1', 'threads/t1', 'messages/m1/attachments/a1']) {
    await assert.rejects(gmailGet({ token: 't', mailbox: 'me', path, fetchImpl }), /nicht konfiguriert/, path);
  }
  await assert.rejects(getMessage({ token: 't', mailbox: 'me', id: 'm1', fetchImpl }), /nicht konfiguriert/);
  assert.equal(log.length, 0);
  assert.equal((await gmailGet({ token: 't', mailbox: 'me', path: 'profile', fetchImpl })).emailAddress, 'x@example.org');
});

test('unkonfiguriert: Versand-Sperre mit Standardtext', async () => {
  await assert.rejects(gmailPost({ token: 't', path: 'messages/send', body: {}, fetchImpl: async () => { throw new Error('nie'); } }), (e) => e instanceof GmailSendBlockedError && e.message.includes(SEND_BLOCKED_DEFAULT));
});
