import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { serviceAccountAssertion, serviceAccountScopes, SA_SCOPES } from '../src/google-auth.js';
import { tmpDir } from './helpers/tmpdir.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const sa = {
  client_email: 'jobs@test.iam.gserviceaccount.com',
  private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  token_uri: 'https://oauth2.googleapis.com/token',
};

test('Dienstkonto-JWT: RS256-signiert, nur Sheets-Scope, 1 h gültig', () => {
  const jwt = serviceAccountAssertion(sa, 1_700_000_000);
  const [kopf, inhalt, sig] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(kopf, 'base64url')), { alg: 'RS256', typ: 'JWT' });
  const claims = JSON.parse(Buffer.from(inhalt, 'base64url'));
  assert.deepEqual(claims, {
    iss: sa.client_email, scope: SA_SCOPES, aud: 'https://oauth2.googleapis.com/token',
    iat: 1_700_000_000, exp: 1_700_003_600,
  });
  assert.equal(SA_SCOPES, 'https://www.googleapis.com/auth/spreadsheets');
  assert.ok(createVerify('RSA-SHA256').update(`${kopf}.${inhalt}`).verify(publicKey, Buffer.from(sig, 'base64url')));
});

test('Dienstkonto-Datei ohne Schlüssel → klarer Fehler', () => {
  assert.throws(() => serviceAccountAssertion({ client_email: 'x' }), /private_key/);
});

test('getAccessToken: mit GOOGLE_SERVICE_ACCOUNT_FILE nur Dienstkonto, Fehler ohne Schlüsselinhalt', async () => {
  const dir = tmpDir('sa-');
  const datei = path.join(dir, 'sa.json');
  writeFileSync(datei, JSON.stringify(sa));
  const alt = { env: process.env.GOOGLE_SERVICE_ACCOUNT_FILE, fetch: globalThis.fetch };
  const aufrufe = [];
  globalThis.fetch = async (url, opt) => {
    aufrufe.push({ url, body: String(opt.body) });
    return { ok: true, json: async () => ({ access_token: 'ya29.test', expires_in: 3600 }) };
  };
  process.env.GOOGLE_SERVICE_ACCOUNT_FILE = datei;
  try {
    const { getAccessToken } = await import(`../src/google-auth.js?t=${Date.now()}`);
    assert.equal(await getAccessToken(), 'ya29.test');
    assert.equal(aufrufe.length, 1);
    assert.equal(aufrufe[0].url, 'https://oauth2.googleapis.com/token');
    assert.match(aufrufe[0].body, /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/);
    assert.doesNotMatch(aufrufe[0].body, /refresh_token/);

    process.env.GOOGLE_SERVICE_ACCOUNT_FILE = path.join(dir, 'fehlt.json');
    const { getAccessToken: g2 } = await import(`../src/google-auth.js?t=${Date.now() + 1}`);
    await assert.rejects(g2(), (e) => /nicht lesbar/.test(e.message) && !e.message.includes('PRIVATE KEY'));

    writeFileSync(datei, JSON.stringify(sa));
    process.env.GOOGLE_SERVICE_ACCOUNT_FILE = datei;
    globalThis.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant', error_description: 'Invalid JWT Signature.' }) });
    const { getAccessToken: g3 } = await import(`../src/google-auth.js?t=${Date.now() + 2}`);
    await assert.rejects(g3(), /invalid_grant/);
  } finally {
    globalThis.fetch = alt.fetch;
    if (alt.env === undefined) delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE; else process.env.GOOGLE_SERVICE_ACCOUNT_FILE = alt.env;
  }
});

test('Cache trennt Zugangsarten: gecachtes OAuth-Token gilt nicht fürs Dienstkonto', async () => {
  const dir = tmpDir('sa-');
  const tokenDir = path.join(dir, '.config', 'gsheets');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(tokenDir, { recursive: true });
  writeFileSync(path.join(tokenDir, 'token.json'), JSON.stringify({ client_id: 'c', client_secret: 's', refresh_token: 'r' }));
  const alt = { home: process.env.HOME, env: process.env.GOOGLE_SERVICE_ACCOUNT_FILE, fetch: globalThis.fetch };
  for (const k of ['GOOGLE_OAUTH_REFRESH_TOKEN', 'GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET']) delete process.env[k];
  process.env.HOME = dir;
  delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE;
  globalThis.fetch = async (url, opt) => ({ ok: true, json: async () => ({ access_token: String(opt.body).includes('refresh_token') ? 'oauth-token' : 'sa-token', expires_in: 3600 }) });
  try {
    const { getAccessToken } = await import(`../src/google-auth.js?cache=${Date.now()}`);
    assert.equal(await getAccessToken(), 'oauth-token');
    process.env.GOOGLE_SERVICE_ACCOUNT_FILE = path.join(dir, 'fehlt.json');
    await assert.rejects(getAccessToken(), /nicht lesbar/);   // kein Rückfall auf das gecachte OAuth-Token
    const sadatei = path.join(dir, 'sa.json');
    writeFileSync(sadatei, JSON.stringify(sa));
    process.env.GOOGLE_SERVICE_ACCOUNT_FILE = sadatei;
    assert.equal(await getAccessToken(), 'sa-token');
  } finally {
    globalThis.fetch = alt.fetch;
    process.env.HOME = alt.home;
    if (alt.env === undefined) delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE; else process.env.GOOGLE_SERVICE_ACCOUNT_FILE = alt.env;
  }
});

test('Delegiertes Dienstkonto: sub + eigene Scopes im JWT, Cache je Postfach', async () => {
  const { getDelegatedToken } = await import(`../src/google-auth.js?t=${Date.now() + 10}`);
  const dir = tmpDir('sa-del-');
  const datei = path.join(dir, 'sa.json');
  writeFileSync(datei, JSON.stringify(sa));
  const alt = globalThis.fetch;
  const claims = [];
  globalThis.fetch = async (url, opt) => {
    const jwt = new URLSearchParams(String(opt.body)).get('assertion');
    claims.push(JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')));
    return { ok: true, json: async () => ({ access_token: `tok${claims.length}`, expires_in: 3600 }) };
  };
  try {
    const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];
    assert.equal(await getDelegatedToken({ datei, sub: 'a@x.de', scopes }), 'tok1');
    assert.equal(await getDelegatedToken({ datei, sub: 'a@x.de', scopes }), 'tok1');   // Cache
    assert.equal(await getDelegatedToken({ datei, sub: 'b@x.de', scopes }), 'tok2');   // anderes Postfach
    assert.equal(claims[0].sub, 'a@x.de');
    assert.equal(claims[0].scope, scopes[0]);
    await assert.rejects(getDelegatedToken({ datei, scopes }), /Pflicht/);
  } finally {
    globalThis.fetch = alt;
  }
});

const SHEETS = 'https://www.googleapis.com/auth/spreadsheets';
const DRIVE = 'https://www.googleapis.com/auth/drive';

test('GOOGLE_SERVICE_ACCOUNT_SCOPES: ungesetzt/leer → nur Sheets, Liste mit Leerzeichen oder Komma', () => {
  assert.equal(serviceAccountScopes(undefined), SA_SCOPES);
  assert.equal(serviceAccountScopes(''), SA_SCOPES);
  assert.equal(serviceAccountScopes('   '), SA_SCOPES);
  assert.equal(serviceAccountScopes(`${SHEETS} ${DRIVE}`), `${SHEETS} ${DRIVE}`);
  assert.equal(serviceAccountScopes(`${SHEETS},${DRIVE}`), `${SHEETS} ${DRIVE}`);
  assert.equal(serviceAccountScopes(` ${SHEETS} , ${DRIVE} ${SHEETS} `), `${SHEETS} ${DRIVE}`);   // doppelt → einmal
  assert.equal(serviceAccountScopes(`${DRIVE}.readonly`), `${DRIVE}.readonly`);
});

test('GOOGLE_SERVICE_ACCOUNT_SCOPES: fremde URLs und Gmail → Abbruch mit klarer Meldung', () => {
  for (const falsch of [
    'drive', 'http://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/', 'https://evil.example/auth/drive',
    'https://www.googleapis.com/AUTH/drive', 'HTTPS://www.googleapis.com/auth/drive', 'https://WWW.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive/../gmail.send', 'https://www.googleapis.com.evil/auth/drive', `${SHEETS};${DRIVE}`,
  ]) {
    assert.throws(() => serviceAccountScopes(falsch), /keine erlaubte Scope-URL/, falsch);
  }
  for (const gmail of ['gmail.compose', 'gmail.send', 'gmail.readonly', 'gmail.modify', 'GMAIL.compose', 'gmail']) {
    assert.throws(() => serviceAccountScopes(`${SHEETS} https://www.googleapis.com/auth/${gmail}`), /Gmail-Scope .* nicht erlaubt/, gmail);
  }
  assert.throws(() => serviceAccountScopes(`${SHEETS} https://mail.google.com/`), /keine erlaubte Scope-URL/);
  for (const nurTrenner of [',', ', ,', ' , ', ',,']) {
    assert.throws(() => serviceAccountScopes(nurTrenner), /nur Trennzeichen/, JSON.stringify(nurTrenner));
  }
});

test('getAccessToken: JWT-scope trägt GOOGLE_SERVICE_ACCOUNT_SCOPES, ohne Variable unverändert, Cache je Scope', async () => {
  const dir = tmpDir('sa-scopes-');
  const datei = path.join(dir, 'sa.json');
  writeFileSync(datei, JSON.stringify(sa));
  const alt = { env: process.env.GOOGLE_SERVICE_ACCOUNT_FILE, scopes: process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES, fetch: globalThis.fetch };
  const claims = [];
  globalThis.fetch = async (url, opt) => {
    const jwt = new URLSearchParams(String(opt.body)).get('assertion');
    claims.push(JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')));
    return { ok: true, json: async () => ({ access_token: `tok${claims.length}`, expires_in: 3600 }) };
  };
  process.env.GOOGLE_SERVICE_ACCOUNT_FILE = datei;
  delete process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES;
  try {
    const { getAccessToken } = await import(`../src/google-auth.js?scopes=${Date.now()}`);
    assert.equal(await getAccessToken(), 'tok1');
    assert.equal(claims[0].scope, SHEETS);                 // ohne Variable exakt wie bisher
    assert.equal(claims[0].sub, undefined);                // nie Delegation

    process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES = `${SHEETS} ${DRIVE}`;
    assert.equal(await getAccessToken(), 'tok2');          // Sheets-only-Token gilt nicht für Drive
    assert.equal(claims[1].scope, `${SHEETS} ${DRIVE}`);
    assert.equal(await getAccessToken(), 'tok2');          // gleicher Scope → Cache
    assert.equal(claims.length, 2);

    process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES = `${SHEETS} https://www.googleapis.com/auth/gmail.compose`;
    await assert.rejects(getAccessToken(), /Gmail-Scope/); // auch bei warmem Cache: Abbruch, kein Token
    assert.equal(claims.length, 2);

    process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES = '';
    assert.equal(await getAccessToken(), 'tok3');          // leer = ungesetzt: wieder nur Sheets, frisches Token
    assert.equal(claims[2].scope, SHEETS);
  } finally {
    globalThis.fetch = alt.fetch;
    for (const [k, v] of [['GOOGLE_SERVICE_ACCOUNT_FILE', alt.env], ['GOOGLE_SERVICE_ACCOUNT_SCOPES', alt.scopes]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});

test('getServiceAccountToken: nur die genannten Scopes, eigener Cache, Gmail-Scope abgelehnt', async (t) => {
  const { getServiceAccountToken } = await import(`../src/google-auth.js?eigen=${Date.now()}`);
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const dir = tmpDir('ga-eigen-', t);
  const datei = path.join(dir, 'sa.json');
  writeFileSync(datei, JSON.stringify({ client_email: 'jobs@test.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  const scopes = [];
  const fetchImpl = async (_u, init) => {
    const claim = JSON.parse(Buffer.from(new URLSearchParams(String(init.body)).get('assertion').split('.')[1], 'base64url').toString());
    scopes.push(claim.scope);
    return { ok: true, status: 200, json: async () => ({ access_token: `AT${scopes.length}`, expires_in: 3600 }) };
  };
  const content = 'https://www.googleapis.com/auth/content';
  assert.equal(await getServiceAccountToken({ datei, scopes: [content], fetchImpl }), 'AT1');
  assert.equal(await getServiceAccountToken({ datei, scopes: [content], fetchImpl }), 'AT1', 'aus dem Cache');
  assert.deepEqual(scopes, [content]);
  await assert.rejects(getServiceAccountToken({ datei, scopes: ['https://www.googleapis.com/auth/gmail.readonly'], fetchImpl }), /Gmail-Scope/);
  await assert.rejects(getServiceAccountToken({ datei, scopes: [], fetchImpl }), /Pflicht/);
});

test('kaputte Token-Antwort: feste Meldung ohne Fragment, Token mit Steuerzeichen abgelehnt', async (t) => {
  const { getDelegatedToken } = await import(`../src/google-auth.js?kaputt=${Date.now()}`);
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const dir = tmpDir('ga-kaputt-', t);
  const datei = path.join(dir, 'sa.json');
  writeFileSync(datei, JSON.stringify({ client_email: 'jobs@test.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  const kaputt = async () => ({ ok: true, status: 200, json: async () => JSON.parse('{"access_token":FAKE_SECRET_SENTINEL}') });
  await assert.rejects(getDelegatedToken({ datei, sub: 'a@example.org', scopes: ['s1'], fetchImpl: kaputt }), (e) => !/FAKE|SECRE/.test(e.message) && /kein gültiges JSON/.test(e.message));
  const zeile = async () => ({ ok: true, status: 200, json: async () => ({ access_token: 'ya29.ab\ncd', expires_in: 3600 }) });
  await assert.rejects(getDelegatedToken({ datei, sub: 'b@example.org', scopes: ['s2'], fetchImpl: zeile }), (e) => !/ya29/.test(e.message) && /ohne gültiges access_token/.test(e.message));
});
