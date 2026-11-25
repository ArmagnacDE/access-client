// access-read access (src/read/inventory.js), S110 (Diagnose Konten und Scopes): zeigt je 1Password-Token-Datei und
// je Google-Credential-Datei, was da ist und was es darf, nie Werte. Ohne Netz und ohne echtes op: 1Password ist ein
// Fake-exec, Google eine Attrappe, alle Dateien liegen mit erfundenen Werten in Wegwerf-Ordnern.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { tmpDir } from './helpers/tmpdir.mjs';
import { run } from '../src/read/cli.js';

const A = 'https://www.googleapis.com/auth/';
const GEHEIM = 'GEHEIM-WERT-0815';
const TOK_A = `ops_${'A'.repeat(30)}${GEHEIM}`;
const TOK_B = `ops_${'B'.repeat(30)}${GEHEIM}`;
const TOK_KAPUTT = `ops_${'K'.repeat(30)}${GEHEIM}`;
const PEM = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });

/** Ordner mit 1Password-Token-Dateien und Google-Credentials anlegen. */
function bestand(t) {
  const op = tmpDir('inv-op-', t);
  const g = tmpDir('inv-g-', t);
  const schreib = (d, n, inhalt, mode = 0o600) => { const p = path.join(d, n); fs.writeFileSync(p, inhalt); fs.chmodSync(p, mode); return p; };
  schreib(op, 'ai-ads.token', `${TOK_A}\n`);
  schreib(op, 'james.token', TOK_B);
  schreib(op, 'customs.token', TOK_A, 0o400);        // Rechte nicht 600: wird gezeigt, nicht gelesen
  schreib(op, 'kaputt.token', TOK_KAPUTT);            // op lehnt das Token ab
  schreib(op, 'notiz.txt', GEHEIM);                   // keine Token-Datei: nur Name
  fs.symlinkSync(path.join(op, 'james.token'), path.join(op, 'link.token'));
  schreib(g, 'token.json', JSON.stringify({ refresh_token: `RT-voll-${GEHEIM}`, client_id: 'cid', client_secret: `CS-${GEHEIM}` }));
  schreib(g, 'token-read-shop.json', JSON.stringify({ refresh_token: `RT-lesen-${GEHEIM}`, client_id: 'cid', client_secret: `CS-${GEHEIM}` }));
  schreib(g, 'token-tot.json', JSON.stringify({ refresh_token: `RT-tot-${GEHEIM}`, client_id: 'cid', client_secret: `CS-${GEHEIM}` }));
  schreib(g, 'sa-jobs.json', JSON.stringify({ type: 'service_account', client_email: 'jobs@projekt.iam.gserviceaccount.com', private_key: PEM, private_key_id: `KID-${GEHEIM}`, token_uri: 'https://oauth2.googleapis.com/token' }));
  schreib(g, 'oauth-client.json', JSON.stringify({ installed: { client_id: 'cid', client_secret: `CS-${GEHEIM}`, project_id: 'projekt' } }));
  schreib(g, 'kaputt.json', `{ "refresh_token": "${GEHEIM}`);
  schreib(g, 'liesmich.txt', GEHEIM, 0o644);
  return { op, g };
}

/** Fake-exec für op: antwortet je Token. */
function opFake() {
  const aufrufe = [];
  const exec = (cmd, args, opts, cb) => {
    const token = opts.env.OP_SERVICE_ACCOUNT_TOKEN;
    aufrufe.push({ cmd, args, token });
    const tresore = { [TOK_A]: ['ai-ads'], [TOK_B]: ['ai-zwei', 'ai-eins'] }[token];
    let r;
    if (!tresore) r = { err: Object.assign(new Error('Command failed'), { code: 1 }), stderr: `[ERROR] 2026/11/24 10:00:00 Invalid service account token ${token}` };
    else if (args[0] === 'whoami') r = { stdout: JSON.stringify({ url: 'https://beispiel.1password.eu', email: `${tresore[0]}@x.1passwordserviceaccounts.eu`, user_type: 'SERVICE_ACCOUNT', user_uuid: 'U' }) };
    else if (args[0] === 'vault' && args[1] === 'list') r = { stdout: JSON.stringify(tresore.map((name, i) => ({ id: `id${i}${GEHEIM}`, name }))) };
    else r = { err: Object.assign(new Error('x'), { code: 1 }), stderr: '[ERROR] unerwartet' };
    queueMicrotask(() => cb(r.err ?? null, Buffer.from(r.stdout ?? ''), Buffer.from(r.stderr ?? '')));
  };
  return { exec, aufrufe };
}

/** Google-Attrappe: Refresh je refresh_token, tokeninfo je Access-Token, Dienstkonto-Grant. */
function google() {
  const log = [];
  const scopes = { [`RT-voll-${GEHEIM}`]: `${A}drive ${A}gmail.modify`, [`RT-lesen-${GEHEIM}`]: `${A}gmail.readonly ${A}drive.readonly` };
  const f = async (url, init = {}) => {
    const u = new URL(url);
    const body = new URLSearchParams(String(init.body ?? ''));
    log.push({ method: init.method ?? 'GET', path: u.pathname, grant: body.get('grant_type') });
    const ok = (b, status = 200) => ({ ok: status < 400, status, json: async () => b });
    if (u.pathname === '/token' && body.get('grant_type') === 'refresh_token') {
      const s = scopes[body.get('refresh_token')];
      return s ? ok({ access_token: `AT-${s.length}`, expires_in: 3600 }) : ok({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' }, 400);
    }
    if (u.pathname === '/token') return ok({ access_token: 'AT-sa', expires_in: 3600 });
    if (u.pathname === '/tokeninfo') {
      const at = body.get('access_token');
      const s = Object.values(scopes).find((x) => `AT-${x.length}` === at);
      return s ? ok({ scope: s, email: 'x@example.org' }) : ok({ error: 'invalid_token' }, 400);
    }
    return ok({ error: 'unbekannt' }, 404);
  };
  return { f, log };
}

async function call(argv, deps) {
  let out = '';
  let err = '';
  const code = await run(argv, { ...deps, stdout: { write: (s) => { out += s; } }, stderr: { write: (s) => { err += s; } } });
  return { code, out, err, json: out ? JSON.parse(out) : null };
}

const nachName = (liste) => Object.fromEntries(liste.map((x) => [x.datei.split('/').pop(), x]));

test('access ohne --check: Dateien, Rechte und Typ ohne Werte; kein op, kein Netz, keine read.json nötig', async (t) => {
  const { op, g } = bestand(t);
  const o = opFake();
  const goo = google();
  const env = { ACCESS_OP_DIR: op, GOOGLE_CONFIG_DIR: g, ACCESS_READ_CONFIG: path.join(op, 'gibt-es-nicht.json') };
  const r = await call(['access'], { env, opExec: o.exec, fetchImpl: goo.f });
  assert.equal(r.code, 0, r.err);
  assert.ok(!r.out.includes(GEHEIM), 'kein Wert in der Ausgabe');
  assert.ok(!r.out.includes('BEGIN PRIVATE'), 'kein Schlüssel in der Ausgabe');
  assert.equal(o.aufrufe.length, 0);
  assert.equal(goo.log.length, 0);
  assert.equal(r.json.onepassword.ordner, op);
  const ops = nachName(r.json.onepassword.dateien);
  assert.deepEqual(Object.keys(ops).sort(), ['ai-ads.token', 'customs.token', 'james.token', 'kaputt.token', 'link.token', 'notiz.txt']);
  assert.equal(ops['ai-ads.token'].rechte, '600');
  assert.equal(ops['ai-ads.token'].brauchbar, true);
  assert.equal(ops['customs.token'].rechte, '400');
  assert.equal(ops['customs.token'].brauchbar, false);
  assert.match(ops['customs.token'].grund, /600/);
  assert.equal(ops['link.token'].brauchbar, false);
  assert.match(ops['link.token'].grund, /Symlink/);
  assert.equal(ops['notiz.txt'].brauchbar, false);
  assert.equal(ops['ai-ads.token'].tresore, undefined, 'Tresore nur mit --check');
  const gs = nachName(r.json.google.dateien);
  assert.equal(r.json.google.ordner, g);
  assert.equal(gs['token.json'].typ, 'oauth-token');
  assert.equal(gs['token-read-shop.json'].typ, 'oauth-token');
  assert.equal(gs['sa-jobs.json'].typ, 'dienstkonto');
  assert.equal(gs['sa-jobs.json'].email, 'jobs@projekt.iam.gserviceaccount.com');
  assert.equal(gs['oauth-client.json'].typ, 'oauth-client');
  assert.equal(gs['kaputt.json'].typ, 'unlesbar');
  assert.equal(gs['liesmich.txt'].typ, 'keine JSON-Datei');
  assert.equal(gs['liesmich.txt'].rechte, '644');
  assert.equal(gs['token.json'].scopes, undefined, 'Scopes nur mit --check');
});

test('access --check: Tresore je Token über op-read, Scopes je Google-Token, Fehler je Datei geschwärzt', async (t) => {
  const { op, g } = bestand(t);
  const o = opFake();
  const goo = google();
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: op, GOOGLE_CONFIG_DIR: g }, opExec: o.exec, fetchImpl: goo.f });
  assert.equal(r.code, 0, r.err);
  assert.ok(!r.out.includes(GEHEIM), 'kein Wert in der Ausgabe');
  assert.ok(!r.out.includes('ops_'), 'kein Token in der Ausgabe');
  const ops = nachName(r.json.onepassword.dateien);
  assert.deepEqual(ops['ai-ads.token'].tresore, ['ai-ads']);
  assert.deepEqual(ops['james.token'].tresore, ['ai-eins', 'ai-zwei']);
  assert.deepEqual(ops['james.token'].konto, { typ: 'SERVICE_ACCOUNT', email: 'ai-zwei@x.1passwordserviceaccounts.eu', url: 'https://beispiel.1password.eu' });
  assert.match(ops['kaputt.token'].fehler, /Token ungültig oder widerrufen/);
  assert.equal(ops['customs.token'].tresore, undefined, 'unbrauchbare Datei: kein op-Aufruf');
  // op nur für die drei brauchbaren Dateien, nur whoami und vault list
  assert.deepEqual([...new Set(o.aufrufe.map((a) => a.token))].sort(), [TOK_A, TOK_B, TOK_KAPUTT].sort());
  for (const a of o.aufrufe) assert.ok(a.args[0] === 'whoami' || (a.args[0] === 'vault' && a.args[1] === 'list'), a.args.join(' '));
  const gs = nachName(r.json.google.dateien);
  assert.deepEqual(gs['token.json'].scopes, ['drive', 'gmail.modify']);
  assert.deepEqual(gs['token-read-shop.json'].scopes, ['drive.readonly', 'gmail.readonly']);
  assert.match(gs['token-tot.json'].fehler, /invalid_grant/);
  assert.equal(gs['sa-jobs.json'].anmeldung, 'ok');
  assert.match(gs['sa-jobs.json'].scopes, /Admin-Konsole/);
  assert.equal(gs['oauth-client.json'].scopes, undefined);
  // Google: nur Token-Endpunkt und tokeninfo, keine API
  for (const l of goo.log) assert.ok(['/token', '/tokeninfo'].includes(l.path), l.path);
});

test('access: fehlende Ordner sind ein Befund, kein Abbruch', async (t) => {
  const leer = tmpDir('inv-leer-', t);
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: path.join(leer, 'op'), GOOGLE_CONFIG_DIR: path.join(leer, 'g') }, opExec: opFake().exec, fetchImpl: google().f });
  assert.equal(r.code, 0, r.err);
  assert.match(r.json.onepassword.fehler, /fehlt/);
  assert.deepEqual(r.json.onepassword.dateien, []);
  assert.match(r.json.google.fehler, /fehlt/);
});

test('access: unbekannte Option und Zusatzargumente sind Aufruffehler', async () => {
  assert.equal((await call(['access', 'x'], { env: {} })).code, 2);
  assert.equal((await call(['access', '--max', '3'], { env: {} })).code, 2);
});

// Codex-Befunde A1–A5 (S110 (Diagnose Konten und Scopes)): Werte auch in Pfaden, erlaubten Feldern und Fehlerpfaden nie
// ausgeben; eine Sonderdatei hält den Lauf nicht an.
test('access --check: tokenartige Namen, Tresornamen, op-stderr und Google-Fehlertexte geben nie Werte aus', async (t) => {
  const op = tmpDir('inv-op2-', t);
  const g = tmpDir('inv-g2-', t);
  const TOK_C = `ops_${'C'.repeat(30)}${GEHEIM}`;
  const TOK_D = `ops_${'D'.repeat(30)}${GEHEIM}`;
  const NAME_TOKEN = `ops_${'N'.repeat(30)}`;
  const VAULT_ID = 'abcdefghijklmnopqrstuvwxyz';
  for (const [n, v] of [[`${NAME_TOKEN}.token`, TOK_A], ['c.token', TOK_C], ['d.token', TOK_D]]) { fs.writeFileSync(path.join(op, n), v); fs.chmodSync(path.join(op, n), 0o600); }
  fs.writeFileSync(path.join(g, `${NAME_TOKEN}.json`), '{}');
  fs.writeFileSync(path.join(g, 'token-tot.json'), JSON.stringify({ refresh_token: `RT-tot-${GEHEIM}`, client_id: 'cid', client_secret: `CS-${GEHEIM}` }));
  const exec = (cmd, args, opts, cb) => {
    const tok = opts.env.OP_SERVICE_ACCOUNT_TOKEN;
    let r;
    if (tok === TOK_C) r = args[0] === 'whoami' ? { stdout: JSON.stringify({ user_type: 'SERVICE_ACCOUNT', url: TOK_C }) } : { stdout: JSON.stringify([{ id: 'x', name: TOK_C }]) };
    else if (tok === TOK_D) r = { err: Object.assign(new Error('Command failed'), { code: 1 }), stderr: `[ERROR] 2026/11/25 10:00:00 vault ${VAULT_ID} failed: ${GEHEIM}` };
    else r = args[0] === 'whoami' ? { stdout: JSON.stringify({ user_type: 'SERVICE_ACCOUNT' }) } : { stdout: JSON.stringify([{ id: 'x', name: 'ai-ads' }]) };
    queueMicrotask(() => cb(r.err ?? null, Buffer.from(r.stdout ?? ''), Buffer.from(r.stderr ?? '')));
  };
  // Google spiegelt Zugangsdaten in einer langen Fehlerantwort zurück
  const fetchImpl = async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant', error_description: `${'x'.repeat(180)} 1//0${GEHEIM} CS-${GEHEIM}` }) });
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: op, GOOGLE_CONFIG_DIR: g }, opExec: exec, fetchImpl });
  assert.equal(r.code, 0, r.err);
  for (const w of [GEHEIM, 'ops_', VAULT_ID, '1//']) assert.ok(!r.out.includes(w), `Ausgabe enthält ${w}`);
  const ops = nachName(r.json.onepassword.dateien);
  assert.deepEqual(ops['c.token'].tresore, ['[Name nicht ausgegeben]']);
  assert.equal(ops['c.token'].konto.url, null);
  assert.match(ops['d.token'].fehler, /op meldet einen Fehler/);
  assert.match(nachName(r.json.google.dateien)['token-tot.json'].fehler, /invalid_grant/);
});

test('access --check: oauth-client.json als FIFO hält den Lauf nicht an; unlesbare Dateien mit Grund', async (t) => {
  const { execFileSync } = await import('node:child_process');
  const g = tmpDir('inv-g3-', t);
  fs.writeFileSync(path.join(g, 'token-ohne-client.json'), JSON.stringify({ refresh_token: `RT-${GEHEIM}` }));
  fs.writeFileSync(path.join(g, 'kaputt.json'), '{');
  execFileSync('mkfifo', [path.join(g, 'oauth-client.json')]);
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: path.join(g, 'fehlt'), GOOGLE_CONFIG_DIR: g }, opExec: opFake().exec, fetchImpl: google().f });
  assert.equal(r.code, 0, r.err);
  const gs = nachName(r.json.google.dateien);
  assert.match(gs['token-ohne-client.json'].fehler, /oauth-client\.json/);
  assert.equal(gs['oauth-client.json'].art, 'sonstiges');
  assert.equal(gs['kaputt.json'].typ, 'unlesbar');
  assert.match(gs['kaputt.json'].grund, /kein gültiges JSON/);
});

// Codex-Folgerunde (S110 (Diagnose Konten und Scopes)): ops_ ohne Wortgrenze, leere client-Felder, flache oauth-client.json.
test('access: ops_ mitten im Namen geschwärzt; leere client-Felder prüfen oauth-client.json; flache oauth-client.json gilt', async (t) => {
  const { execFileSync } = await import('node:child_process');
  const g = tmpDir('inv-g4-', t);
  const NAME = `backup_ops_${'Q'.repeat(30)}.json`;
  fs.writeFileSync(path.join(g, NAME), '{}');
  fs.writeFileSync(path.join(g, 'token-leer.json'), JSON.stringify({ refresh_token: `RT-${GEHEIM}`, client_id: '', client_secret: '' }));
  execFileSync('mkfifo', [path.join(g, 'oauth-client.json')]);
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: path.join(g, 'fehlt'), GOOGLE_CONFIG_DIR: g }, opExec: opFake().exec, fetchImpl: google().f });
  assert.equal(r.code, 0, r.err);
  assert.ok(!r.out.includes('Q'.repeat(30)), 'Name mit ops_ geschwärzt');
  assert.match(nachName(r.json.google.dateien)['token-leer.json'].fehler, /oauth-client\.json/);

  const g2 = tmpDir('inv-g5-', t);
  fs.writeFileSync(path.join(g2, 'token-ohne-client.json'), JSON.stringify({ refresh_token: `RT-lesen-${GEHEIM}` }));
  fs.writeFileSync(path.join(g2, 'oauth-client.json'), JSON.stringify({ client_id: 'cid', client_secret: `CS-${GEHEIM}` }));
  const alt = process.env.GOOGLE_CONFIG_DIR;
  process.env.GOOGLE_CONFIG_DIR = g2;   // google-auth liest oauth-client.json aus process.env
  try {
    const r2 = await call(['access', '--check'], { env: { ACCESS_OP_DIR: path.join(g2, 'fehlt'), GOOGLE_CONFIG_DIR: g2 }, opExec: opFake().exec, fetchImpl: google().f });
    const gs = nachName(r2.json.google.dateien);
    assert.equal(gs['oauth-client.json'].typ, 'oauth-client');
    assert.deepEqual(gs['token-ohne-client.json'].scopes, ['drive.readonly', 'gmail.readonly']);
    assert.ok(!r2.out.includes(GEHEIM));
  } finally { if (alt === undefined) delete process.env.GOOGLE_CONFIG_DIR; else process.env.GOOGLE_CONFIG_DIR = alt; }
});

// reviewer-Befunde (S110 (Diagnose Konten und Scopes)): harmlose ops_-Namen bleiben, Tresorliste ohne whoami,
// Refresh nur gegen Googles Token-Endpunkt und nur mit derselben Client-Quelle wie google-auth.
test('access --check: „Shops_Archiv“ bleibt lesbar, Token-Name wird einzeln ersetzt; whoami-Fehler kostet die Tresorliste nicht', async (t) => {
  const op = tmpDir('inv-op6-', t);
  const g = tmpDir('inv-g6-', t);
  fs.writeFileSync(path.join(g, 'shops_export.json'), '{}');
  fs.writeFileSync(path.join(op, 'a.token'), TOK_A); fs.chmodSync(path.join(op, 'a.token'), 0o600);
  const exec = (cmd, args, opts, cb) => {
    const r = args[0] === 'whoami'
      ? { err: Object.assign(new Error('x'), { code: 1 }), stderr: '[ERROR] unknown command' }
      : { stdout: JSON.stringify([{ name: 'Shops_Archiv' }, { name: `ops_${'T'.repeat(40)}` }, { name: 'ai-ads' }]) };
    queueMicrotask(() => cb(r.err ?? null, Buffer.from(r.stdout ?? ''), Buffer.from(r.stderr ?? '')));
  };
  const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: op, GOOGLE_CONFIG_DIR: g }, opExec: exec, fetchImpl: google().f });
  assert.equal(r.code, 0, r.err);
  const d = r.json.onepassword.dateien[0];
  assert.deepEqual(d.tresore, ['[Name nicht ausgegeben]', 'ai-ads', 'Shops_Archiv']);
  assert.match(d.kontoFehler, /op meldet einen Fehler/);
  assert.ok(!r.out.includes('T'.repeat(40)));
  assert.ok(r.json.google.dateien.some((x) => x.datei.endsWith('/shops_export.json')), 'harmloser Dateiname bleibt');
});

test('access --check: kein Refresh bei fremder token_uri oder abweichender Client-Quelle', async (t) => {
  const g = tmpDir('inv-g7-', t);
  fs.writeFileSync(path.join(g, 'token-fremd.json'), JSON.stringify({ refresh_token: `RT-lesen-${GEHEIM}`, client_id: 'cid', client_secret: `CS-${GEHEIM}`, token_uri: 'https://beispiel.example/token' }));
  fs.writeFileSync(path.join(g, 'token-ohne-client.json'), JSON.stringify({ refresh_token: `RT-lesen-${GEHEIM}` }));
  fs.writeFileSync(path.join(g, 'oauth-client.json'), JSON.stringify({ installed: { client_id: 'cid', client_secret: `CS-${GEHEIM}` } }));
  const goo = google();
  const alt = process.env.GOOGLE_CONFIG_DIR;
  process.env.GOOGLE_CONFIG_DIR = path.join(g, 'anderswo');   // google-auth läse oauth-client.json woanders
  try {
    const r = await call(['access', '--check'], { env: { ACCESS_OP_DIR: path.join(g, 'fehlt'), GOOGLE_CONFIG_DIR: g }, opExec: opFake().exec, fetchImpl: goo.f });
    const gs = nachName(r.json.google.dateien);
    assert.match(gs['token-fremd.json'].fehler, /token_uri/);
    assert.match(gs['token-ohne-client.json'].fehler, /oauth-client\.json/);
    assert.equal(goo.log.length, 0, 'kein Aufruf an irgendeinen Endpunkt');
  } finally { if (alt === undefined) delete process.env.GOOGLE_CONFIG_DIR; else process.env.GOOGLE_CONFIG_DIR = alt; }
});

test('googleFehler ordnet ohne den Pfad ein; opFehler kennt Signal und nicht ausführbar', async () => {
  const { googleFehler, opFehler } = await import('../src/read/inventory.js');
  const datei = '/x/token-invalid_client-tokeninfo.json';
  assert.equal(googleFehler(new Error(`Google-Anmeldung mit ${datei} fehlgeschlagen: invalid_grant Token has been expired`), datei), 'Google: Anmeldung fehlgeschlagen (invalid_grant)');
  assert.equal(googleFehler(new Error(`Google-Anmeldung mit ${datei} fehlgeschlagen: 400`), datei), 'Google: Anmeldung fehlgeschlagen');
  assert.equal(opFehler(new Error('1Password: Kontoabfrage fehlgeschlagen: op beendet durch SIGKILL')), '1Password: op beendet durch SIGKILL');
  assert.equal(opFehler(new Error('1Password: Kontoabfrage fehlgeschlagen: op nicht ausführbar (EACCES)')), '1Password: op nicht ausführbar (EACCES)');
});
