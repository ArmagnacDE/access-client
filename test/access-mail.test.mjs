// access-mail (src/mail/*) und der Mail-Weg über das delegierte Dienstkonto (S112 „Ein Mail-Weg für Sessions und
// Agenten“): Entwürfe in einem frei wählbaren Postfach der Domain, Antwort in einen Verlauf, Anhänge; Senden ist nicht
// erreichbar. Ohne Netz: Google ist eine Attrappe, der Dienstkonto-Schlüssel ein frisch erzeugter Test-Schlüssel.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { tmpDir } from './helpers/tmpdir.mjs';
import { run as runMail, USAGE as MAIL_USAGE } from '../src/mail/cli.js';
import { run as runRead } from '../src/read/cli.js';
import { validateConfig, resolveMailbox } from '../src/read/accounts.js';

const A = 'https://www.googleapis.com/auth/';
const COMPOSE = `${A}gmail.compose`;
const READONLY = `${A}gmail.readonly`;
const DOM = 'example.org';
const KONFIG = {
  accounts: { owner: { email: `owner@${DOM}`, token: 'token-read-owner.json' } },
  filesAccount: 'owner',
  gmailBlockedLabel: 'agent-no-read',
  mailDelegation: { key: 'sa-mail-test.json', domains: [DOM] },
};
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const SA = { type: 'service_account', client_email: 'mail-test@p.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };

const claimsOf = (assertion) => JSON.parse(Buffer.from(String(assertion).split('.')[1], 'base64url').toString('utf8'));

/** Google-Attrappe: Token-Endpunkt (Dienstkonto, JWT), Gmail profile/labels/messages/drafts. Echte Postfächer: boxes. */
function google({ boxes = [`sascha@${DOM}`, `hello@${DOM}`, `mail@${DOM}`, `warehouse@${DOM}`], mails = {} } = {}) {
  const log = [];
  const tokens = new Map();
  const f = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? 'GET';
    log.push({ method, url: String(url), host: u.host, path: decodeURIComponent(u.pathname), q: Object.fromEntries(u.searchParams), body: init.body });
    const ok = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
    if (u.host === 'oauth2.googleapis.com') {
      const c = claimsOf(new URLSearchParams(String(init.body)).get('assertion'));
      if (!boxes.includes(c.sub)) return ok({ error: 'invalid_grant', error_description: 'Invalid email or User ID' }, 400);
      const at = `AT-${tokens.size + 1}`;
      tokens.set(at, { sub: c.sub, scope: c.scope });
      return ok({ access_token: at, expires_in: 3600, scope: c.scope, token_type: 'Bearer' });
    }
    const who = tokens.get(String(init.headers?.Authorization ?? '').replace('Bearer ', ''));
    if (!who) return ok({ error: { message: 'unauthenticated' } }, 401);
    if (u.host !== 'gmail.googleapis.com') return ok({ error: { message: 'unerwartet' } }, 500);
    const [box, ...rest] = decodeURIComponent(u.pathname).split('/').slice(4);
    if (box !== who.sub) return ok({ error: { message: 'Delegation denied' } }, 403);
    const p = rest.join('/');
    if (method === 'GET') {
      if (p === 'profile') return ok({ emailAddress: who.sub });
      if (!who.scope.includes('gmail.readonly')) return ok({ error: { message: 'Request had insufficient authentication scopes.' } }, 403);
      if (p === 'labels') return ok({ labels: [{ id: 'INBOX', name: 'INBOX' }, { id: 'Label_S', name: 'agent-no-read' }] });
      if (p === 'messages') return ok({ messages: Object.keys(mails).map((id) => ({ id, threadId: `t-${id}` })) });
      const m = /^messages\/([^/]+)$/.exec(p);
      if (m && mails[m[1]]) {
        const x = mails[m[1]];
        return ok({ id: m[1], threadId: `t-${m[1]}`, labelIds: x.labels, payload: { headers: Object.entries(x.headers).map(([name, value]) => ({ name, value })) } });
      }
      return ok({ error: { message: 'not found' } }, 404);
    }
    if (method === 'POST' && p === 'drafts') {
      if (!who.scope.includes('gmail.compose')) return ok({ error: { message: 'insufficient scopes' } }, 403);
      return ok({ id: 'r-123', message: { id: 'm-new', threadId: JSON.parse(init.body).message.threadId ?? 't-new' } });
    }
    return ok({ error: { message: `nicht in der Attrappe: ${method} ${p}` } }, 405);
  };
  f.log = log;
  return f;
}

function setup(t, konfig = KONFIG) {
  const dir = tmpDir('access-mail-', t);
  const ablage = path.join(dir, 'ablage');
  fs.mkdirSync(ablage);
  fs.writeFileSync(path.join(dir, 'sa-mail-test.json'), JSON.stringify(SA), { mode: 0o600 });
  const cfg = path.join(dir, 'read.json');
  fs.writeFileSync(cfg, JSON.stringify({ downloadDirs: [ablage], ...konfig }));
  return { dir, ablage, env: { ...process.env, GOOGLE_CONFIG_DIR: dir, ACCESS_READ_CONFIG: cfg } };
}

async function call(run, argv, deps) {
  let out = ''; let err = '';
  const code = await run(argv, { ...deps, stdout: { write: (s) => { out += s; } }, stderr: { write: (s) => { err += s; } } });
  return { code, out, err, json: code === 0 ? JSON.parse(out) : null };
}
const draftCalls = (f) => f.log.filter((c) => c.method !== 'GET' && c.host === 'gmail.googleapis.com');
const rawOf = (c) => Buffer.from(JSON.parse(c.body).message.raw, 'base64url').toString('utf8');
const scopesAngefragt = (f) => f.log.filter((c) => c.host === 'oauth2.googleapis.com').map((c) => {
  const k = claimsOf(new URLSearchParams(String(c.body)).get('assertion'));
  return [k.sub, k.scope];
});

// ---------------------------------------------------------------------------------------------------------------
// Konfiguration und Postfach-Auflösung
// ---------------------------------------------------------------------------------------------------------------
test('mailDelegation: Schlüssel nur als Dateiname, Domains Pflicht; unbekannte Felder abgelehnt', () => {
  assert.ok(validateConfig(KONFIG).mailDelegation);
  for (const md of [{ key: '../x.json', domains: [DOM] }, { key: 'token.json', domains: [DOM] }, { key: 'sa.json', domains: [] },
    { key: 'sa.json', domains: ['nicht domain'] }, { key: 'sa.json', domains: [DOM], extra: 1 }]) {
    assert.throws(() => validateConfig({ ...KONFIG, mailDelegation: md }), /mailDelegation/);
  }
});

test('resolveMailbox: Kurzname, Adresse und Konto-Name der Domain → delegiert; fremde Domain abgelehnt', () => {
  const c = validateConfig(KONFIG);
  assert.deepEqual([resolveMailbox(c, 'hello').email, resolveMailbox(c, 'Warehouse@Example.org').email, resolveMailbox(c, 'owner').email],
    [`hello@${DOM}`, `warehouse@${DOM}`, `owner@${DOM}`]);
  assert.equal(resolveMailbox(c, 'hello').kind, 'delegated');
  assert.equal(resolveMailbox(c, 'hello').file, 'sa-mail-test.json');
  assert.throws(() => resolveMailbox(c, 'kunde@fremd.example'), /nicht in der Domain/);
  assert.throws(() => resolveMailbox(c, 'a b'), /ungültig/);
});

// ---------------------------------------------------------------------------------------------------------------
// access-read mail über die Delegierung
// ---------------------------------------------------------------------------------------------------------------
test('access-read mail <postfach> liest über das Dienstkonto, angefragt nur gmail.readonly; Drive bleibt beim Konto', async (t) => {
  const { env } = setup(t);
  const f = google({ mails: { aa11bb22: { labels: ['INBOX'], headers: { From: 'a@b.example', Subject: 'Hallo' } } } });
  const r = await call(runRead, ['mail', 'hello', 'search', 'newer_than:7d'], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  assert.equal(r.json.konto, `hello@${DOM}`);
  assert.equal(r.json.anzahl, 1);
  assert.deepEqual([...new Set(scopesAngefragt(f).map((x) => x[1]))], [READONLY]);
  assert.ok(f.log.every((c) => c.method === 'GET' || c.host === 'oauth2.googleapis.com'));
});

// ---------------------------------------------------------------------------------------------------------------
// access-mail draft
// ---------------------------------------------------------------------------------------------------------------
test('draft: Entwurf im gewählten Postfach, nur gmail.compose, Text als text/plain, Ausgabe nennt „nicht gesendet“', async (t) => {
  const { env } = setup(t);
  const f = google();
  const r = await call(runMail, ['draft', '--from', 'hello', '--to', 'kunde@kunde.example', '--subject', 'Ihre Bestellung', '--body', 'Hallo,\nanbei.'], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  assert.equal(r.json.postfach, `hello@${DOM}`);
  assert.equal(r.json.entwurfId, 'r-123');
  assert.match(r.json.hinweis, /nicht gesendet/i);
  assert.deepEqual([...new Set(scopesAngefragt(f).map((x) => x.join(' ')))], [`hello@${DOM} ${COMPOSE}`]);
  const d = draftCalls(f);
  assert.equal(d.length, 1);
  assert.equal(d[0].path, `/gmail/v1/users/hello@${DOM}/drafts`);
  const raw = rawOf(d[0]);
  assert.match(raw, /^To: kunde@kunde\.example\r\n/m);
  assert.match(raw, /Content-Type: text\/plain; charset="UTF-8"/);
  assert.match(Buffer.from(raw.split('\r\n\r\n')[1].replace(/\r\n/g, ''), 'base64').toString('utf8'), /Hallo,\nanbei\./);
});

test('draft --from außerhalb der Domain oder unbekanntes echtes Konto: nichts angelegt', async (t) => {
  const { env } = setup(t);
  const f = google();
  const r = await call(runMail, ['draft', '--from', 'jemand@fremd.example', '--to', 'x@y.example', '--subject', 's', '--body', 'b'], { fetchImpl: f, env });
  assert.equal(r.code, 1);
  assert.equal(f.log.length, 0, 'kein Netzzugriff');
  const g = google();
  const s = await call(runMail, ['draft', '--from', 'belege', '--to', 'x@y.example', '--subject', 's', '--body', 'b'], { fetchImpl: g, env });
  assert.equal(s.code, 1);
  assert.match(s.err, /kein eigenes Postfach|Alias|invalid_grant/);
  assert.equal(draftCalls(g).length, 0);
});

test('draft --reply-to: Verlauf, In-Reply-To/References, Empfänger aus Reply-To, Betreff „Re: …“', async (t) => {
  const { env } = setup(t);
  const f = google({ mails: { abc123def: { labels: ['INBOX'], headers: { From: 'Kunde <k@kunde.example>', 'Reply-To': 'service@kunde.example', Subject: 'Frage zur Lieferung', 'Message-ID': '<orig@kunde.example>', References: '<alt@kunde.example>' } } } });
  const r = await call(runMail, ['draft', '--from', 'mail', '--reply-to', 'abc123def', '--body', 'Danke!'], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  const d = draftCalls(f);
  assert.equal(d.length, 1);
  assert.equal(JSON.parse(d[0].body).message.threadId, 't-abc123def');
  const raw = rawOf(d[0]);
  assert.match(raw, /^To: service@kunde\.example\r\n/m);
  assert.match(raw, /In-Reply-To: <orig@kunde\.example>/);
  assert.match(raw, /References: <alt@kunde\.example> <orig@kunde\.example>/);
  assert.match(raw, /Subject: Re: Frage zur Lieferung/);
  assert.deepEqual([...new Set(scopesAngefragt(f).map((x) => x[1]))].sort(), [COMPOSE, READONLY].sort());
});

test('draft --reply-to auf eine Sicherheitsmail: gesperrt, kein Entwurf', async (t) => {
  const { env } = setup(t);
  const f = google({ mails: { def456abc: { labels: ['INBOX', 'Label_S'], headers: { From: 'noreply@bank.example', Subject: 'Ihr Code', 'Message-ID': '<c@bank.example>' } } } });
  const r = await call(runMail, ['draft', '--from', 'mail', '--reply-to', 'def456abc', '--body', 'x'], { fetchImpl: f, env });
  assert.equal(r.code, 1);
  assert.match(r.err, /Sicherheitsmail/);
  assert.equal(draftCalls(f).length, 0);
});

test('draft --attach und --body-file nur aus den Ablage-Ordnern; Anhang als multipart/mixed', async (t) => {
  const { env, ablage, dir } = setup(t);
  fs.writeFileSync(path.join(ablage, 'text.html'), '<p>Hallo</p>');
  fs.writeFileSync(path.join(ablage, 'Rechnung März.pdf'), Buffer.from('%PDF-1.4 test'));
  const f = google();
  const r = await call(runMail, ['draft', '--from', 'sascha', '--to', 'a@b.example', '--subject', 'Rechnung', '--body-file', path.join(ablage, 'text.html'), '--html',
    '--attach', path.join(ablage, 'Rechnung März.pdf')], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  const raw = rawOf(draftCalls(f)[0]);
  assert.match(raw, /Content-Type: multipart\/mixed; boundary="/);
  assert.match(raw, /Content-Type: text\/html; charset="UTF-8"/);
  assert.match(raw, /filename\*=UTF-8''Rechnung%20M%C3%A4rz\.pdf/);
  assert.deepEqual(r.json.anhaenge, [{ datei: 'Rechnung März.pdf', bytes: 13 }]);
  // Schlüsseldatei liegt außerhalb der Ablage: weder als Anhang noch als Text
  const g = google();
  for (const args of [['--attach', path.join(dir, 'sa-mail-test.json'), '--body', 'x'], ['--body-file', path.join(dir, 'sa-mail-test.json')]]) {
    const s = await call(runMail, ['draft', '--from', 'sascha', '--to', 'a@b.example', '--subject', 's', ...args], { fetchImpl: g, env });
    assert.equal(s.code, 1, args.join(' '));
    assert.match(s.err, /Ablage-Ordner|downloadDirs/);
  }
  assert.equal(g.log.length, 0, 'geprüft vor jedem Netzzugriff');
});

test('draft: Zeilenumbruch in Empfänger oder Betreff abgelehnt (keine fremden Kopfzeilen)', async (t) => {
  const { env } = setup(t);
  const f = google();
  for (const a of [['--to', 'a@b.example\r\nBcc: x@y.example', '--subject', 's'], ['--to', 'a@b.example', '--subject', 's\nBcc: x@y.example']]) {
    const r = await call(runMail, ['draft', '--from', 'hello', ...a, '--body', 'b'], { fetchImpl: f, env });
    assert.notEqual(r.code, 0);
  }
  assert.equal(draftCalls(f).length, 0);
});

// ---------------------------------------------------------------------------------------------------------------
// Pflichttest: Sendepfade sind nicht erreichbar
// ---------------------------------------------------------------------------------------------------------------
test('Senden ist nicht erreichbar: kein Unterbefehl, keine Option, keine Anfrage führt zu einem Versand-Endpunkt', async (t) => {
  const { env, ablage } = setup(t);
  fs.writeFileSync(path.join(ablage, 'b.txt'), 'x');
  const f = google({ mails: { abc123def: { labels: ['INBOX'], headers: { From: 'k@k.example', Subject: 'S', 'Message-ID': '<o@k.example>' } } } });
  const versuche = [
    ['send', '--from', 'hello', '--to', 'a@b.example', '--subject', 's', '--body', 'b'],
    ['draft', '--send', '--from', 'hello', '--to', 'a@b.example', '--subject', 's', '--body', 'b'],
    ['draft', '--from', 'hello', '--to', 'a@b.example', '--subject', 's', '--body', 'b', '--now'],
    ['drafts/send', '--from', 'hello'],
    ['draft', '--from', 'hello/drafts/send', '--to', 'a@b.example', '--subject', 's', '--body', 'b'],
    ['draft', '--from', 'hello%2Fsend', '--to', 'a@b.example', '--subject', 's', '--body', 'b'],
    ['draft', '--from', 'me', '--to', 'a@b.example', '--subject', 's', '--body', 'b'],
    ['draft', '--from', 'hello', '--reply-to', '../send', '--body', 'b'],
    ['draft', '--from', 'hello', '--reply-to', 'abc123def/send', '--body', 'b'],
    ['update', 'r-123', '--send'],
    ['draft', '--from', 'hello', '--to', 'a@b.example', '--subject', 's', '--body-file', path.join(ablage, 'b.txt')],
    ['draft', '--from', 'hello', '--reply-to', 'abc123def', '--body', 'b'],
  ];
  for (const v of versuche) await call(runMail, v, { fetchImpl: f, env });
  for (const c of f.log) {
    assert.ok(!/\/send\b|sendas|%2fsend/i.test(c.url), `Versand-URL erreicht: ${c.method} ${c.url}`);
    if (c.host === 'gmail.googleapis.com' && c.method !== 'GET') {
      assert.equal(c.method, 'POST', c.url);
      assert.match(c.path, /^\/gmail\/v1\/users\/[^/]+@example\.org\/drafts$/, 'nur drafts.create');
    }
  }
  assert.equal(draftCalls(f).length, 2, 'nur die zwei gültigen Entwürfe');
  assert.doesNotMatch(MAIL_USAGE, /\bsend\b/i);
});

test('access-mail kennt im Code nur drafts.create über createCheckedDraft (kein gmailPost, kein PUT/DELETE, kein Senden)', () => {
  const ROOT = path.resolve(import.meta.dirname, '..');
  const dateien = [...fs.readdirSync(path.join(ROOT, 'src/mail')).map((f) => `src/mail/${f}`), 'bin/access-mail.mjs'];
  for (const d of dateien) {
    const src = fs.readFileSync(path.join(ROOT, d), 'utf8');
    for (const m of ['PUT', 'PATCH', 'DELETE']) assert.ok(!new RegExp(`['"\`]${m}['"\`]`).test(src), `${d}: ${m}`);
    const imp = [...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'([^']+)'/g)].flatMap((m) => m[1].split(',').map((x) => x.trim().split(/\s+as\s+/)[0]));
    for (const w of ['gmailPost', 'createDraft', 'readPortalCodeMails']) assert.ok(!imp.includes(w), `${d}: importiert ${w}`);
    assert.ok(!/fetchImpl\(|globalThis\.fetch\(|\bfetch\(/.test(src.replace(/\/\/.*$/gm, '')), `${d}: eigener Netzaufruf`);
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.bin['access-mail'], 'bin/access-mail.mjs');
});

test('Codex S112 #4: Anzeigename mit Komma in Anführungszeichen bleibt eine Adresse', async () => {
  const { addressList } = await import('../src/mail/draft.js');
  assert.deepEqual(addressList('"Doe, Jane" <jane@example.org>, b@example.org', 'to'), ['"Doe, Jane" <jane@example.org>', 'b@example.org']);
  assert.throws(() => addressList('"offen <a@b.example>', 'to'), /keine Adresse/);
});

test('resolveMailbox: Konto mit eigenem Token außerhalb der Delegierungs-Domain behält seinen Zugang', () => {
  const c = validateConfig({ ...KONFIG, accounts: { ...KONFIG.accounts, privat: { email: 'p@other.example', token: 'token-read-p.json' } } });
  const a = resolveMailbox(c, 'privat');
  assert.deepEqual([a.kind, a.file], ['token', 'token-read-p.json']);
  assert.throws(() => resolveMailbox(c, 'x@other.example'), /nicht in der Domain/);
});

test('reviewer S112 B1: access-read search blendet gesperrte Treffer aus statt abzubrechen', async (t) => {
  const { env } = setup(t);
  const f = google({ mails: { aa11bb22: { labels: ['INBOX'], headers: { From: 'a@b.example', Subject: 'Hallo' } }, cc33dd44: { labels: ['INBOX'], headers: { From: 'x@y.example', Subject: 'Dein Code lautet 1' } } } });
  const r = await call(runRead, ['mail', 'hello', 'search', 'x'], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  assert.equal(r.json.anzahl, 1);
  assert.equal(r.json.ausgeblendet, 1);
});

test('reviewer S112 B2: --attach/--body-file aus einem Git-Repo unterhalb der Ablage abgelehnt', async (t) => {
  const { env, ablage } = setup(t);
  fs.mkdirSync(path.join(ablage, 'repo', '.git'), { recursive: true });
  fs.writeFileSync(path.join(ablage, 'repo', 'geheim.txt'), 'x');
  const f = google();
  const r = await call(runMail, ['draft', '--from', 'hello', '--to', 'a@b.example', '--subject', 's', '--body-file', path.join(ablage, 'repo', 'geheim.txt')], { fetchImpl: f, env });
  assert.equal(r.code, 1);
  assert.match(r.err, /Git-Repo/);
  assert.equal(f.log.length, 0);
});

test('reviewer S112 B3: Entwurf nur über den Schlüssel der Mail-Delegierung, nie über ein anderes delegated-Konto', async (t) => {
  const { env } = setup(t, { ...KONFIG, accounts: { ...KONFIG.accounts, ext: { email: 'x@fremd.example', delegated: 'sa-alt.json' } } });
  const f = google();
  const r = await call(runMail, ['draft', '--from', 'ext', '--to', 'a@b.example', '--subject', 's', '--body', 'b'], { fetchImpl: f, env });
  assert.equal(r.code, 1);
  assert.match(r.err, /nur über die Mail-Delegierung/);
  const { mailDelegation, ...ohne } = KONFIG;
  const { env: env2 } = setup(t, { ...ohne, accounts: { ext: { email: 'x@fremd.example', delegated: 'sa-alt.json' } }, filesAccount: undefined });
  const s = await call(runMail, ['draft', '--from', 'ext', '--to', 'a@b.example', '--subject', 's', '--body', 'b'], { fetchImpl: f, env: env2 });
  assert.equal(s.code, 1);
  assert.match(s.err, /nur über die Mail-Delegierung/);
  assert.equal(f.log.length, 0);
});

test('reviewer S112 N1/N2/N12: Antwort auf eigene Mail geht an deren Empfänger; @ im Anzeigenamen; Prototyp-Namen', async (t) => {
  const { env } = setup(t);
  const f = google({ mails: { ee55ff66: { labels: ['SENT'], headers: { From: `Mail <mail@${DOM}>`, To: 'Kunde <k@kunde.example>', Subject: 'Re: Frage', 'Message-ID': '<m@x.example>' } } } });
  const r = await call(runMail, ['draft', '--from', 'mail', '--reply-to', 'ee55ff66', '--body', 'Nachtrag'], { fetchImpl: f, env });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.json.an, ['Kunde <k@kunde.example>']);
  const { addressList } = await import('../src/mail/draft.js');
  assert.throws(() => addressList('kunde@firma.example <angreifer@evil.example>', 'to'), /keine Adresse/);
  const c = validateConfig(KONFIG);
  for (const w of ['constructor', 'toString']) assert.equal(resolveMailbox(c, w).email, `${w.toLowerCase()}@${DOM}`);
  assert.throws(() => resolveMailbox(c, '__proto__'), /ungültig/);
});
