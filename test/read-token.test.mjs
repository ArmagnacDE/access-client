// S137 (Mail-Wächter-Job live): Lese-Token für Drive/Sheets/Docs eines Kontos erzeugen (scripts/read-token.mjs).
// Zwei Schritte, weil die Zustimmung im Browser des Inhabers passiert: start (URL + PKCE, Zwischenstand 600) und
// finish (Code gegen Token, nur Lese-Scopes, richtiges Konto, neue Datei 600, nie überschreiben). Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { READ_TOKEN_SCOPES, startReadToken, finishReadToken } from '../src/token-setup.js';
import { tmpDir } from './helpers/tmpdir.mjs';

const ACCOUNT = { name: 'owner', email: 'owner@example.org', file: 'token-read-owner.json', kind: 'token' };
const CLIENT = { installed: { client_id: 'cid.apps.googleusercontent.com', client_secret: 'geheim' } };
const idToken = (email) => `x.${Buffer.from(JSON.stringify({ email, email_verified: true })).toString('base64url')}.y`;

function umgebung() {
  const dir = tmpDir('read-token-');
  const gdir = path.join(dir, 'gsheets'); const sdir = path.join(dir, 'state');
  return { gdir, sdir, opts: { googleDir: gdir, stateDir: sdir, client: CLIENT, random: (n) => Buffer.alloc(n, 7) } };
}

test('start: URL nur mit Lese-Scopes, PKCE S256, offline, login_hint; Zwischenstand 600 ohne Geheimnis', () => {
  const { sdir, opts } = umgebung();
  const r = startReadToken(ACCOUNT, opts);
  const u = new URL(r.url);
  assert.equal(u.origin + u.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.deepEqual(u.searchParams.get('scope').split(' ').sort(), [...READ_TOKEN_SCOPES].sort());
  for (const s of READ_TOKEN_SCOPES) assert.ok(/readonly$|userinfo\.email$|^openid$/.test(s), s);
  assert.equal(u.searchParams.get('access_type'), 'offline');
  assert.equal(u.searchParams.get('prompt'), 'consent');
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('login_hint'), 'owner@example.org');
  assert.match(u.searchParams.get('redirect_uri'), /^http:\/\/127\.0\.0\.1:\d+\/$/);
  assert.equal(statSync(r.pending).mode & 0o777, 0o600);
  assert.ok(!readFileSync(r.pending, 'utf8').includes('geheim'), 'kein Client-Secret im Zwischenstand');
  assert.ok(r.pending.startsWith(sdir));
});

test('start: bestehende Token-Datei wird nie überschrieben', () => {
  const { gdir, opts } = umgebung();
  startReadToken(ACCOUNT, opts); // legt Ordner an
  writeFileSync(path.join(gdir, ACCOUNT.file), '{}');
  assert.throws(() => startReadToken(ACCOUNT, opts), /existiert schon/);
});

async function bisFinish(antwort, { url } = {}) {
  const u = umgebung();
  const r = startReadToken(ACCOUNT, u.opts);
  const state = new URL(r.url).searchParams.get('state');
  const calls = [];
  const fetchImpl = async (adr, o) => { calls.push({ adr, o }); return { ok: antwort.ok ?? true, status: antwort.status ?? 200, json: async () => antwort.json }; };
  const redirectUrl = url ?? `http://127.0.0.1:8765/?state=${state}&code=4/abc&scope=x`;
  return { u, calls, res: finishReadToken(ACCOUNT, redirectUrl, { ...u.opts, fetchImpl }) };
}

test('finish: schreibt neue Token-Datei 600 nur mit refresh_token und Scope, nichts davon in der Rückgabe', async () => {
  const { u, calls, res } = await bisFinish({ json: { access_token: 'ya29.a', refresh_token: '1//r', scope: READ_TOKEN_SCOPES.join(' '), id_token: idToken('owner@example.org') } });
  const r = await res;
  const datei = path.join(u.gdir, ACCOUNT.file);
  assert.equal(statSync(datei).mode & 0o777, 0o600);
  const t = JSON.parse(readFileSync(datei, 'utf8'));
  assert.equal(t.refresh_token, '1//r');
  assert.equal(t.access_token, undefined, 'kein Access-Token in der Datei');
  assert.equal(t.client_secret, undefined, 'Client kommt aus oauth-client.json');
  assert.ok(!JSON.stringify(r).includes('1//r') && !JSON.stringify(r).includes('ya29'), 'Rückgabe ohne Token');
  assert.equal(calls[0].o.redirect, 'error');
  assert.equal(calls[0].o.method, 'POST');
  assert.ok(String(calls[0].o.body).includes('code_verifier='));
  assert.equal(existsSync(path.join(u.sdir, 'read-token-owner.json')), false, 'Zwischenstand aufgeräumt');
});

test('finish: falsches Google-Konto, mehr Rechte, fremder state oder kein refresh_token → nichts geschrieben', async () => {
  const faelle = [
    [{ json: { access_token: 'a', refresh_token: 'r', scope: READ_TOKEN_SCOPES.join(' '), id_token: idToken('privat@example.com') } }, /anderem Konto/],
    [{ json: { access_token: 'a', refresh_token: 'r', scope: `${READ_TOKEN_SCOPES.join(' ')} https://www.googleapis.com/auth/drive`, id_token: idToken('owner@example.org') } }, /andere Rechte/],
    [{ json: { access_token: 'a', scope: READ_TOKEN_SCOPES.join(' '), id_token: idToken('owner@example.org') } }, /refresh_token fehlt/],
    [{ ok: false, status: 400, json: { error: 'invalid_grant' } }, /invalid_grant/],
    [{ json: { access_token: 'a', refresh_token: 'r', scope: READ_TOKEN_SCOPES.join(' ') } }, /anderem Konto/], // ohne id_token
    [{ json: { access_token: 'a', refresh_token: 'r', scope: READ_TOKEN_SCOPES.filter((x) => !x.includes('spreadsheets')).join(' '), id_token: idToken('owner@example.org') } }, /ohne spreadsheets/],
  ];
  for (const [antwort, fehler] of faelle) {
    const { u, res } = await bisFinish(antwort);
    await assert.rejects(res, fehler);
    assert.equal(existsSync(path.join(u.gdir, ACCOUNT.file)), false, String(fehler));
  }
  const { u, calls, res } = await bisFinish({ json: {} }, { url: 'http://127.0.0.1:8765/?state=falsch&code=4/abc' });
  await assert.rejects(res, /state/);
  assert.equal(calls.length, 0, 'ohne passenden state kein Token-Abruf');
  assert.equal(existsSync(path.join(u.gdir, ACCOUNT.file)), false);
});

test('finish: unbekannter Fehlercode aus der URL erscheint nicht wörtlich; bekannter schon (Codex S137)', async () => {
  const u = umgebung();
  startReadToken(ACCOUNT, u.opts);
  await assert.rejects(finishReadToken(ACCOUNT, 'http://127.0.0.1:8765/?error=synthetic-secret', { ...u.opts, fetchImpl: async () => { throw new Error('nie'); } }),
    (e) => !e.message.includes('synthetic') && /Google/.test(e.message));
  await assert.rejects(finishReadToken(ACCOUNT, 'http://127.0.0.1:8765/?error=access_denied', { ...u.opts, fetchImpl: async () => { throw new Error('nie'); } }), /access_denied/);
});

test('finish: ein neuer start während des Tauschs bleibt erhalten (Codex S137)', async () => {
  const u = umgebung();
  const r = startReadToken(ACCOUNT, u.opts);
  const state = new URL(r.url).searchParams.get('state');
  let neu;
  const fetchImpl = async () => {
    neu = startReadToken(ACCOUNT, { ...u.opts, random: (n) => Buffer.alloc(n, 9) }); // Inhaber startet parallel neu
    return { ok: true, status: 200, json: async () => ({ access_token: 'a', refresh_token: 'r', scope: READ_TOKEN_SCOPES.join(' '), id_token: idToken('owner@example.org') }) };
  };
  await finishReadToken(ACCOUNT, `http://127.0.0.1:8765/?state=${state}&code=4/abc`, { ...u.opts, fetchImpl });
  assert.ok(existsSync(neu.pending), 'Zwischenstand des neuen Starts nicht gelöscht');
});
