// S40 (Google-Schlüssel ohne Datei): Dienstkonto-Schlüssel als Wert statt Pfad (src/google-auth.js).
// Kein Netz: fetch ist eine Attrappe. Der Schlüssel wird je Lauf neu erzeugt (erfunden, kein echtes Dienstkonto).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpDir } from './helpers/tmpdir.mjs';

const paar = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const a = paar();
const b = paar();
const sa = (k, extra = {}) => ({
  type: 'service_account',
  client_id: '100000000000000000001',
  client_email: 'jobs@test-projekt.iam.gserviceaccount.com',
  private_key_id: 'erfunden-0001',
  private_key: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  ...extra,
});
const keyA = sa(a);
const keyB = sa(b, { client_id: '100000000000000000002', client_email: 'andere@test-projekt.iam.gserviceaccount.com' });

const laden = async (tag) => import(`../src/google-auth.js?wert=${tag}-${Date.now()}-${Math.random()}`);

/** fetch-Attrappe: zeichnet Assertions auf, antwortet mit fortlaufenden Tokens. */
function tokenFetch() {
  const aufrufe = [];
  const fetchImpl = async (url, opt) => {
    const body = new URLSearchParams(String(opt.body));
    aufrufe.push({ url, assertion: body.get('assertion'), grant: body.get('grant_type') });
    return { ok: true, status: 200, json: async () => ({ access_token: `AT${aufrufe.length}`, expires_in: 3600 }) };
  };
  return { fetchImpl, aufrufe };
}
const claims = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));
const signiertMit = (jwt, publicKey) => {
  const [k, i, s] = jwt.split('.');
  return createVerify('RSA-SHA256').update(`${k}.${i}`).verify(publicKey, Buffer.from(s, 'base64url'));
};
// Kein Teil des Schlüssels in einer Meldung: weder PEM-Kopf noch ein Stück aus der Mitte.
const ohneSchluessel = (msg) => !/PRIVATE KEY|MII/.test(msg) && !msg.includes(keyA.private_key.slice(100, 140));

test('parseServiceAccountKey: Objekt, JSON-String und Buffer ergeben denselben Schlüssel', async () => {
  const { parseServiceAccountKey } = await laden('parse');
  for (const wert of [keyA, JSON.stringify(keyA), Buffer.from(JSON.stringify(keyA))]) {
    const k = parseServiceAccountKey(wert);
    assert.equal(k.client_email, keyA.client_email);
    assert.equal(k.private_key, keyA.private_key);
  }
  // Das zurückgegebene Objekt ist eine eigene Kopie: der Aufrufer darf sein Objekt danach verändern.
  const roh = { ...keyA };
  const k = parseServiceAccountKey(roh);
  roh.private_key = 'x';
  assert.equal(k.private_key, keyA.private_key);
});

test('parseServiceAccountKey: kaputte Werte → feste Meldung ohne Schlüsselinhalt', async () => {
  const { parseServiceAccountKey } = await laden('parse-kaputt');
  const faelle = [
    [JSON.stringify(keyA).slice(0, -5), /kein gültiges JSON/],
    ['', /leer|kein gültiges JSON/],
    [null, /fehlt/],
    [42, /Objekt, JSON-Text oder Buffer/],
    [[keyA], /kein Objekt/],
    [{ ...keyA, type: 'authorized_user' }, /kein Dienstkonto-Schlüssel/],
    [{ ...keyA, private_key: '' }, /private_key/],
    [{ ...keyA, client_email: undefined }, /client_email/],
  ];
  for (const [wert, muster] of faelle) {
    assert.throws(() => parseServiceAccountKey(wert), (e) => muster.test(e.message) && ohneSchluessel(e.message), String(muster));
  }
});

test('parseServiceAccountKey: clientId prüft, dass der richtige Schlüssel kommt', async () => {
  const { parseServiceAccountKey } = await laden('clientid');
  assert.equal(parseServiceAccountKey(keyA, { clientId: '100000000000000000001' }).client_email, keyA.client_email);
  assert.throws(() => parseServiceAccountKey(keyB, { clientId: '100000000000000000001' }), (e) => /anderen Dienstkonto/.test(e.message) && !e.message.includes('100000000000000000002'));
});

test('getDelegatedToken({ key }): signiert mit dem übergebenen Schlüssel, ohne Datei, Cache je Schlüssel', async () => {
  const { getDelegatedToken } = await laden('deleg');
  const { fetchImpl, aufrufe } = tokenFetch();
  const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];
  assert.equal(await getDelegatedToken({ key: keyA, sub: 'a@example.org', scopes, fetchImpl }), 'AT1');
  assert.equal(await getDelegatedToken({ key: JSON.stringify(keyA), sub: 'a@example.org', scopes, fetchImpl }), 'AT1', 'derselbe Schlüssel als Text: Cache');
  assert.equal(aufrufe.length, 1);
  assert.ok(signiertMit(aufrufe[0].assertion, a.publicKey));
  assert.equal(claims(aufrufe[0].assertion).sub, 'a@example.org');
  assert.equal(claims(aufrufe[0].assertion).iss, keyA.client_email);
  // Anderer Schlüssel mit gleichem Postfach: eigener Abruf, nie das Token des ersten.
  assert.equal(await getDelegatedToken({ key: keyB, sub: 'a@example.org', scopes, fetchImpl }), 'AT2');
  assert.ok(signiertMit(aufrufe[1].assertion, b.publicKey));
});

test('getDelegatedToken: gleicher Kontoname, anderer privater Schlüssel → kein geteilter Cache', async () => {
  const { getDelegatedToken } = await laden('deleg-gleichname');
  const { fetchImpl, aufrufe } = tokenFetch();
  const scopes = ['s1'];
  const keyA2 = { ...keyB, client_email: keyA.client_email, client_id: keyA.client_id, private_key_id: keyA.private_key_id };
  await getDelegatedToken({ key: keyA, sub: 'a@example.org', scopes, fetchImpl });
  assert.equal(await getDelegatedToken({ key: keyA2, sub: 'a@example.org', scopes, fetchImpl }), 'AT2');
  assert.equal(aufrufe.length, 2);
});

test('getDelegatedToken: datei und key zugleich oder keins von beiden → Abbruch vor jedem Abruf', async () => {
  const { getDelegatedToken } = await laden('deleg-beides');
  const { fetchImpl, aufrufe } = tokenFetch();
  await assert.rejects(getDelegatedToken({ datei: '/x/sa.json', key: keyA, sub: 'a@example.org', scopes: ['s'], fetchImpl }), /entweder datei oder key/);
  await assert.rejects(getDelegatedToken({ sub: 'a@example.org', scopes: ['s'], fetchImpl }), /Pflicht/);
  await assert.rejects(getDelegatedToken({ key: '{kaputt', sub: 'a@example.org', scopes: ['s'], fetchImpl }), (e) => /kein gültiges JSON/.test(e.message) && !e.message.includes('kaputt'));
  assert.equal(aufrufe.length, 0);
});

test('getDelegatedToken({ datei }) bleibt wie bisher', async (t) => {
  const { getDelegatedToken } = await laden('deleg-datei');
  const datei = path.join(tmpDir('sa-wert-', t), 'sa.json');
  writeFileSync(datei, JSON.stringify(keyA));
  const { fetchImpl, aufrufe } = tokenFetch();
  assert.equal(await getDelegatedToken({ datei, sub: 'a@example.org', scopes: ['s1'], fetchImpl }), 'AT1');
  assert.ok(signiertMit(aufrufe[0].assertion, a.publicKey));
});

test('getServiceAccountToken({ key }): nur die genannten Scopes, Gmail abgelehnt, Cache je Schlüssel', async () => {
  const { getServiceAccountToken } = await laden('eigen');
  const { fetchImpl, aufrufe } = tokenFetch();
  const content = 'https://www.googleapis.com/auth/content';
  assert.equal(await getServiceAccountToken({ key: keyA, scopes: [content], fetchImpl }), 'AT1');
  assert.equal(await getServiceAccountToken({ key: keyA, scopes: [content], fetchImpl }), 'AT1');
  assert.equal(await getServiceAccountToken({ key: keyB, scopes: [content], fetchImpl }), 'AT2');
  assert.equal(claims(aufrufe[0].assertion).scope, content);
  assert.equal(claims(aufrufe[0].assertion).sub, undefined);
  await assert.rejects(getServiceAccountToken({ key: keyA, scopes: ['https://www.googleapis.com/auth/gmail.readonly'], fetchImpl }), /Gmail-Scope/);
  await assert.rejects(getServiceAccountToken({ datei: '/x', key: keyA, scopes: [content], fetchImpl }), /entweder datei oder key/);
});

/** process.env und fetch für einen Test setzen und danach zurück. */
async function mitUmgebung(werte, fn) {
  // Nie echte Credentials: leerer Config-Ordner, keine OAuth-Variablen (ein Rückfall auf den Inhaber scheitert so laut).
  const namen = ['GOOGLE_SERVICE_ACCOUNT_FILE', 'GOOGLE_SERVICE_ACCOUNT_KEY', 'GOOGLE_SERVICE_ACCOUNT_SCOPES', 'GOOGLE_CONFIG_DIR',
    'GOOGLE_OAUTH_REFRESH_TOKEN', 'GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET'];
  const alt = Object.fromEntries(namen.map((n) => [n, process.env[n]]));
  const altFetch = globalThis.fetch;
  for (const n of namen) delete process.env[n];
  process.env.GOOGLE_CONFIG_DIR = tmpDir('sa-wert-leer-');
  Object.assign(process.env, werte);
  const f = tokenFetch();
  globalThis.fetch = f.fetchImpl;
  try { return await fn(f); } finally {
    globalThis.fetch = altFetch;
    for (const n of namen) { if (alt[n] === undefined) delete process.env[n]; else process.env[n] = alt[n]; }
  }
}

test('getAccessToken: GOOGLE_SERVICE_ACCOUNT_KEY (JSON) meldet als Dienstkonto an, ohne Datei', async () => {
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_KEY: JSON.stringify(keyA) }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env');
    assert.equal(await getAccessToken(), 'AT1');
    assert.equal(await getAccessToken(), 'AT1', 'Cache');
    assert.equal(aufrufe.length, 1);
    assert.equal(aufrufe[0].grant, 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    assert.ok(signiertMit(aufrufe[0].assertion, a.publicKey));
    assert.equal(claims(aufrufe[0].assertion).scope, 'https://www.googleapis.com/auth/spreadsheets');
    // Anderer Schlüssel in derselben Variable: neues Token, nie das gecachte.
    process.env.GOOGLE_SERVICE_ACCOUNT_KEY = JSON.stringify(keyB);
    assert.equal(await getAccessToken(), 'AT2');
    assert.ok(signiertMit(aufrufe[1].assertion, b.publicKey));
  });
});

test('getAccessToken: GOOGLE_SERVICE_ACCOUNT_KEY trägt GOOGLE_SERVICE_ACCOUNT_SCOPES', async () => {
  const scopes = 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive';
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_KEY: JSON.stringify(keyA), GOOGLE_SERVICE_ACCOUNT_SCOPES: scopes }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env-scopes');
    await getAccessToken();
    assert.equal(claims(aufrufe[0].assertion).scope, scopes);
  });
});

test('getAccessToken: _FILE und _KEY zugleich → Abbruch; kaputter _KEY → Meldung ohne Inhalt', async (t) => {
  const datei = path.join(tmpDir('sa-wert-', t), 'sa.json');
  writeFileSync(datei, JSON.stringify(keyA));
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_FILE: datei, GOOGLE_SERVICE_ACCOUNT_KEY: JSON.stringify(keyA) }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env-beides');
    await assert.rejects(getAccessToken(), (e) => /GOOGLE_SERVICE_ACCOUNT_FILE und GOOGLE_SERVICE_ACCOUNT_KEY/.test(e.message) && ohneSchluessel(e.message));
    assert.equal(aufrufe.length, 0);
  });
  const kaputt = JSON.stringify(keyA).slice(0, -3);
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_KEY: kaputt }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env-kaputt');
    await assert.rejects(getAccessToken(), (e) => /GOOGLE_SERVICE_ACCOUNT_KEY/.test(e.message) && /kein gültiges JSON/.test(e.message) && ohneSchluessel(e.message));
    assert.equal(aufrufe.length, 0);
  });
});

test('getAccessToken: Wechsel von _FILE auf _KEY nutzt nicht das Token der Datei', async (t) => {
  const datei = path.join(tmpDir('sa-wert-', t), 'sa.json');
  writeFileSync(datei, JSON.stringify(keyA));
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_FILE: datei }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env-wechsel');
    assert.equal(await getAccessToken(), 'AT1');
    delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE;
    process.env.GOOGLE_SERVICE_ACCOUNT_KEY = JSON.stringify(keyB);
    assert.equal(await getAccessToken(), 'AT2');
    assert.equal(aufrufe.length, 2);
    assert.equal(aufrufe[1].grant, 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    assert.ok(signiertMit(aufrufe[1].assertion, b.publicKey));
  });
});

test('getAccessToken: leeres GOOGLE_SERVICE_ACCOUNT_KEY → Abbruch, kein stiller Rückfall auf den Inhaber (Codex S40 A1)', async (t) => {
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_KEY: '' }, async ({ aufrufe }) => {
    // Ein Inhaber-Token läge bereit: der Rückfall darauf wäre der Fehler.
    writeFileSync(path.join(process.env.GOOGLE_CONFIG_DIR, 'token.json'), JSON.stringify({ client_id: 'c', client_secret: 's', refresh_token: 'r-erfunden' }));
    const { getAccessToken } = await laden('env-leer');
    await assert.rejects(getAccessToken(), /GOOGLE_SERVICE_ACCOUNT_KEY ist leer/);
    assert.equal(aufrufe.length, 0);
  });
  const datei = path.join(tmpDir('sa-wert-', t), 'sa.json');
  writeFileSync(datei, JSON.stringify(keyA));
  await mitUmgebung({ GOOGLE_SERVICE_ACCOUNT_FILE: datei, GOOGLE_SERVICE_ACCOUNT_KEY: '' }, async ({ aufrufe }) => {
    const { getAccessToken } = await laden('env-leer-datei');
    await assert.rejects(getAccessToken(), /zugleich gesetzt/);
    assert.equal(aufrufe.length, 0);
  });
});

test('Pflichtmeldungen ohne key wörtlich wie bisher (Codex S40 A3)', async () => {
  const { getDelegatedToken, getServiceAccountToken } = await laden('pflicht');
  await assert.rejects(getDelegatedToken({ datei: '/x/sa.json', scopes: ['s'] }), { message: 'getDelegatedToken: datei, sub und scopes sind Pflicht' });
  await assert.rejects(getDelegatedToken({ sub: 'a@example.org', scopes: ['s'] }), { message: 'getDelegatedToken: datei, sub und scopes sind Pflicht' });
  await assert.rejects(getServiceAccountToken({ datei: '/x/sa.json', scopes: [] }), { message: 'getServiceAccountToken: datei und scopes sind Pflicht' });
  await assert.rejects(getDelegatedToken({ key: keyA, scopes: ['s'] }), { message: 'getDelegatedToken: key, sub und scopes sind Pflicht' });
  await assert.rejects(getServiceAccountToken({ key: keyA, scopes: [] }), { message: 'getServiceAccountToken: key und scopes sind Pflicht' });
});

test('parseServiceAccountKey: private_key, der kein Schlüssel ist → feste Meldung ohne Inhalt (reviewer S40 #4)', async () => {
  const { parseServiceAccountKey } = await laden('pem-kaputt');
  const verstuemmelt = keyA.private_key.replace(/\n/g, '\\n');   // doppelt maskiert, wie nach einem Env-Transport
  assert.throws(() => parseServiceAccountKey({ ...keyA, private_key: verstuemmelt }), (e) => /private_key nicht als Schlüssel lesbar/.test(e.message) && ohneSchluessel(e.message) && e.cause === undefined);
});

test('Wert-Weg: fester Token-Endpunkt, token_uri aus dem Schlüssel zählt nie (reviewer S40 #5)', async () => {
  const { getDelegatedToken } = await laden('tokenuri');
  const { fetchImpl, aufrufe } = tokenFetch();
  await getDelegatedToken({ key: { ...keyA, token_uri: 'https://fremd.example/token' }, sub: 'a@example.org', scopes: ['s1'], fetchImpl });
  assert.equal(aufrufe[0].url, 'https://oauth2.googleapis.com/token');
});

test('serviceAccountSource: key | file | null nach derselben Regel wie getAccessToken (reviewer S40 #3)', async () => {
  const { serviceAccountSource } = await laden('quelle');
  assert.equal(serviceAccountSource({}), null);
  assert.equal(serviceAccountSource({ GOOGLE_SERVICE_ACCOUNT_FILE: '' }), null);
  assert.equal(serviceAccountSource({ GOOGLE_SERVICE_ACCOUNT_FILE: '/x/sa.json' }), 'file');
  assert.equal(serviceAccountSource({ GOOGLE_SERVICE_ACCOUNT_KEY: '{}' }), 'key');
  assert.equal(serviceAccountSource({ GOOGLE_SERVICE_ACCOUNT_KEY: '' }), 'key', 'gesetzt, auch leer: getAccessToken bricht dann ab, nie OAuth');
  assert.throws(() => serviceAccountSource({ GOOGLE_SERVICE_ACCOUNT_FILE: '/x', GOOGLE_SERVICE_ACCOUNT_KEY: '' }), /zugleich gesetzt/);
});
