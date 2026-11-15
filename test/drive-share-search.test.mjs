// src/drive.js: findFilesByName, listPermissions, ensureServiceAccountWriter.
// Ohne Netz: Fake-Zugang über Umgebungsvariablen, fetch nachgebaut. Eigene Datei = eigener Prozess (Token-Cache).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

process.env.GOOGLE_OAUTH_CLIENT_ID = 'cid';
process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'csec';
process.env.GOOGLE_OAUTH_REFRESH_TOKEN = 'rt';
delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE;

const calls = [];
let antworten = [];
globalThis.fetch = async (url, o = {}) => {
  const u = String(url);
  if (u.startsWith('https://oauth2.googleapis.com/token')) return { ok: true, json: async () => ({ access_token: 'AT', expires_in: 3600 }) };
  calls.push({ url: u, method: o.method ?? 'GET', body: o.body });
  const a = antworten.shift() ?? {};
  return { ok: a.ok ?? true, status: a.status ?? 200, json: async () => a.json ?? {}, text: async () => JSON.stringify(a.json ?? {}) };
};

const { findFilesByName, ensureServiceAccountWriter, listPermissions } = await import('../src/drive.js');
const SA = 'jobs@beispiel-projekt-123.iam.gserviceaccount.com';

beforeEach(() => { calls.length = 0; antworten = []; });

test('findFilesByName: Query mit Name, MIME, ohne Papierkorb, alle Ablagen, blättert', async () => {
  antworten = [{ json: { files: [{ id: 'A' }], nextPageToken: 'p2' } }, { json: { files: [{ id: 'B' }] } }];
  const r = await findFilesByName('Entwürfe', 'application/vnd.google-apps.spreadsheet');
  assert.deepEqual(r.map((f) => f.id), ['A', 'B']);
  const q = new URL(calls[0].url).searchParams;
  assert.equal(q.get('q'), "name = 'Entwürfe' and trashed = false and mimeType = 'application/vnd.google-apps.spreadsheet'");
  assert.equal(q.get('corpora'), 'allDrives');
  assert.equal(new URL(calls[1].url).searchParams.get('pageToken'), 'p2');
});

test('findFilesByName: Anführungszeichen im Namen werden maskiert; incompleteSearch → Fehler', async () => {
  antworten = [{ json: { files: [] } }];
  await findFilesByName("O'Brien");
  assert.equal(new URL(calls[0].url).searchParams.get('q'), "name = 'O\\'Brien' and trashed = false");
  antworten = [{ json: { files: [], incompleteSearch: true } }];
  await assert.rejects(findFilesByName('X'), /unvollständig/);
});

test('ensureServiceAccountWriter: nur Dienstkonto-Adressen, nie Person oder Link', async () => {
  for (const bad of ['owner@example.org', 'anyone', '', 'x@gserviceaccount.com', `${SA}.evil.com`]) {
    await assert.rejects(ensureServiceAccountWriter('F', bad), /keine Dienstkonto-Adresse/);
  }
  assert.equal(calls.length, 0, 'kein Aufruf bei verweigerter Adresse');
});

test('ensureServiceAccountWriter: setzt writer ohne Benachrichtigung, nicht doppelt', async () => {
  antworten = [{ json: { permissions: [{ type: 'user', role: 'owner', emailAddress: 'owner@example.org' }] } }, { json: { id: 'p1' } }];
  assert.equal(await ensureServiceAccountWriter('F', SA.toUpperCase()), true);
  assert.equal(calls[1].method, 'POST');
  assert.match(calls[1].url, /\/files\/F\/permissions\?supportsAllDrives=true&sendNotificationEmail=false$/);
  assert.deepEqual(JSON.parse(calls[1].body), { type: 'user', role: 'writer', emailAddress: SA });
  calls.length = 0;
  antworten = [{ json: { permissions: [{ type: 'user', role: 'writer', emailAddress: SA }] } }];
  assert.equal(await ensureServiceAccountWriter('F', SA), false);
  assert.equal(calls.length, 1, 'nur gelesen');
});

test('listPermissions: liefert Liste, Fehler werfen', async () => {
  antworten = [{ json: { permissions: [{ type: 'user', role: 'writer', emailAddress: SA }] } }];
  assert.equal((await listPermissions('F')).length, 1);
  antworten = [{ ok: false, status: 404, json: { error: 'nf' } }];
  await assert.rejects(listPermissions('F'), /Drive API 404/);
});

test('listPermissions blättert (Shared-Drive-Dateien können mehrere Seiten haben)', async () => {
  antworten = [{ json: { permissions: [{ emailAddress: 'a' }], nextPageToken: 'n2' } }, { json: { permissions: [{ emailAddress: SA, role: 'writer', type: 'user' }] } }];
  const r = await listPermissions('F');
  assert.deepEqual(r.map((p) => p.emailAddress), ['a', SA]);
  assert.equal(new URL(calls[1].url).searchParams.get('pageToken'), 'n2');
});
