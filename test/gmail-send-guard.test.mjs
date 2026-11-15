// Gmail-Versand-Wächter: die Entwurfs-Regel im Code erzwingen.
//
// Warum: gmail.compose und gmail.modify dürfen laut Google-Doku (Authorization scopes, Stand 19.10.2026) senden, über
// messages.send und drafts.send. Einen Nur-Entwurf-Scope gibt es nicht. Die Regel „nur Entwürfe, Senden macht ein
// Mensch“ hängt also am Code. Dieser Test hält sie dort:
//   1. statisch: kein Versand-Endpunkt, kein gmail.send-Scope, kein sendAs in src/ und bin/ des Pakets;
//   2. kein direkter Gmail-API-Aufruf außerhalb von src/gmail.js;
//   3. Laufzeit: die Hülle in src/gmail.js lehnt Versand-Pfade ab, auch dynamisch gebaute.
// Jedes Repo, das das Paket nutzt, behält seinen eigenen Repo-Scan.
// Rein, ohne Netz: fetch ist überall eine Attrappe.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { literaleAus } from './helpers/js-literale.mjs';
import {
  GMAIL_COMPOSE, SEND_BLOCKED_DEFAULT, GmailSendBlockedError, assertNoSend, configureGmailGuard, createDraft, gmailGet, gmailPost,
} from '../src/gmail.js';

configureGmailGuard({ blockedLabel: 'agent-no-read', sendBlockedReason: 'Versand nur durch Test-Inhaber (nur Entwürfe)' });

const ROOT = resolve(import.meta.dirname, '..');
const DIRS = ['src', 'bin'];
const EXT = /\.(js|mjs|cjs|sh)$/;

// Muster, die Versand bedeuten. In Kommentaren nur erlaubt, wenn der Kommentar sie verbietet (NEGATION).
const SEND_PATTERNS = [
  { name: 'messages/send', re: /messages\/send/i },
  { name: 'drafts/send', re: /drafts\/send/i },
  { name: 'messages.send', re: /messages\.send/i },
  { name: 'drafts.send', re: /drafts\.send/i },
  { name: 'gmail.send-Scope', re: /gmail\.send\b/i },
  { name: 'sendAs', re: /\bsendAs\b/i },
  { name: 'SMTP Gmail', re: /smtp\.gmail\.com/i },
  { name: 'Gmail batch/upload', re: /googleapis\.com\/(batch|upload)\/gmail/i },
];
const NEGATION = /\b(nie|niemals|nicht|kein\w*|verbiete\w*|verboten|gesperrt|sperr\w*|abgelehnt|never|not|no)\b/i;

// Begründete Ausnahmen für SEND_PATTERNS: Datei + Ausschnitt der Zeile. Jeder Eintrag braucht einen Grund.
const SEND_ALLOW = [
  { file: 'src/gmail.js', line: "s.startsWith('sendas')", reason: 'Sperrliste der Versand-Hülle selbst (assertNoSend lehnt sendAs ab)' },
];

// Dateien, die die Gmail-API direkt ansprechen, statt über lib/gmail.js. Neue Einträge nur mit Grund.
const DIRECT_GMAIL = /gmail\.googleapis\.com|www\.googleapis\.com\/gmail/i;
const DIRECT_ALLOW = {
  'src/gmail.js': 'die Hülle selbst',
};

function* files(dir) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* files(p);
    else if (EXT.test(e.name)) yield p;
  }
}

/** Kommentarbereiche: JS über den Lexer der Meta-Tests, Shell ab „#“ (Zeilenanfang oder nach Leerraum). */
function commentRanges(src, file) {
  if (!file.endsWith('.sh')) {
    // Aufeinanderfolgende Zeilenkommentare zu einem Block zusammenfassen: die Verneinung darf in der Nachbarzeile stehen.
    const blocks = [];
    for (const k of literaleAus(src).kommentare) {
      const prev = blocks.at(-1);
      if (prev && /^\s*$/.test(src.slice(prev.end, k.start))) prev.end = k.end;
      else blocks.push({ ...k });
    }
    return blocks;
  }
  const out = [];
  let pos = 0;
  for (const line of src.split('\n')) {
    const m = /(^|\s)#/.exec(line);
    if (m) {
      const start = pos + m.index + m[1].length;
      const prev = out.at(-1);
      if (prev && /^\s*$/.test(src.slice(prev.end, start))) prev.end = pos + line.length;
      else out.push({ start, end: pos + line.length });
    }
    pos += line.length + 1;
  }
  return out;
}

/** Treffer der Versand-Muster in einem Quelltext; erlaubt sind nur verbietende Kommentare. */
export function sendHits(src, file = 'x.mjs') {
  const comments = commentRanges(src, file);
  const lines = src.split('\n');
  const hits = [];
  for (const { name, re } of SEND_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const m of src.matchAll(g)) {
      const c = comments.find((r) => m.index >= r.start && m.index < r.end);
      if (c && NEGATION.test(src.slice(c.start, c.end))) continue;
      const lineNo = src.slice(0, m.index).split('\n').length;
      hits.push({ name, lineNo, line: lines[lineNo - 1].trim() });
    }
  }
  return hits;
}

const ALL = DIRS.flatMap((d) => [...files(join(ROOT, d))]).map((p) => ({ rel: relative(ROOT, p).split('\\').join('/'), src: readFileSync(p, 'utf8') }));

test('Scan sieht genug Dateien (sonst prüft er ins Leere)', () => {
  assert.ok(ALL.length >= 9, `nur ${ALL.length} Dateien gefunden`);
  for (const f of ['src/gmail.js', 'src/read/cli.js', 'bin/access-read.mjs']) assert.ok(ALL.some((a) => a.rel === f), `${f} fehlt im Scan`);
});

test('Selbsttest der Erkennung: Code-Treffer, verbietender Kommentar, harmloser Kommentar, Shell', () => {
  assert.equal(sendHits("await fetch(base + '/users/me/messages/send', { method: 'POST' });").length, 1);
  assert.equal(sendHits("const u = `${GMAIL}/users/${box}/drafts/send`;").length, 1);
  assert.equal(sendHits("gmail.users.messages.send({ userId: 'me' });").length, 1);
  assert.equal(sendHits("const S = 'https://www.googleapis.com/auth/gmail.send';").length, 1);
  assert.equal(sendHits("await gmailPost({ path: 'settings/sendAs' });").length, 1);
  assert.equal(sendHits('// nie messages.send aufrufen, Versand macht ein Mensch\nconst x = 1;').length, 0);
  assert.equal(sendHits('// gmail.compose erlaubt drafts.send,\n// im Code ist das gesperrt\nconst x = 1;').length, 0);
  assert.equal(sendHits('// hier messages.send nutzen\nconst x = 1;').length, 1, 'Kommentar ohne Verbot zählt');
  assert.equal(sendHits('const sendAsync = 1; resendAt(); // Mail.send-Wörter ohne Endpunkt').length, 0);
  assert.equal(sendHits('curl -X POST "$G/gmail/v1/users/me/messages/send"\n', 'x.sh').length, 1);
  assert.equal(sendHits('# kein drafts/send, Firmenregel\necho ok\n', 'x.sh').length, 0);
});

test('kein Versand-Endpunkt, kein gmail.send-Scope, kein sendAs in src/ und bin/', () => {
  const found = [];
  const usedAllow = new Set();
  for (const { rel, src } of ALL) {
    for (const h of sendHits(src, rel)) {
      const allow = SEND_ALLOW.find((a) => a.file === rel && h.line.includes(a.line));
      if (allow) { usedAllow.add(allow); continue; }
      found.push(`${rel}:${h.lineNo} [${h.name}] ${h.line.slice(0, 120)}`);
    }
  }
  assert.deepEqual(found, [], `Versand-Muster gefunden (${SEND_BLOCKED_DEFAULT}):\n${found.join('\n')}`);
  for (const a of SEND_ALLOW) {
    assert.ok(a.reason?.length > 10, `Ausnahme ohne Begründung: ${a.file}`);
    assert.ok(usedAllow.has(a), `veraltete Ausnahme (trifft nichts mehr, bitte entfernen): ${a.file} „${a.line}“`);
  }
});

test('direkte Gmail-API-Aufrufe nur in src/gmail.js', () => {
  const direct = ALL.filter(({ src }) => DIRECT_GMAIL.test(src)).map((a) => a.rel);
  const unknown = direct.filter((f) => !DIRECT_ALLOW[f]);
  assert.deepEqual(unknown, [], `Gmail-API direkt angesprochen; bitte über gmailPost/gmailGet aus src/gmail.js gehen:\n${unknown.join('\n')}`);
  for (const [f, reason] of Object.entries(DIRECT_ALLOW)) {
    assert.ok(reason.length > 10, `Eintrag ohne Begründung: ${f}`);
    assert.ok(direct.includes(f), `veralteter Eintrag (Datei spricht Gmail nicht mehr direkt an, bitte entfernen): ${f}`);
  }
});

test('GMAIL_COMPOSE ist der Entwurfs-Scope, und src/gmail.js sagt dazu, dass er senden könnte', () => {
  assert.equal(GMAIL_COMPOSE, 'https://www.googleapis.com/auth/gmail.compose');
  const src = readFileSync(join(ROOT, 'src/gmail.js'), 'utf8');
  const i = src.indexOf('export const GMAIL_COMPOSE');
  assert.match(src.slice(Math.max(0, i - 900), i), /Senden[\s\S]*gesperrt/);
});

// ---------------------------------------------------------------------------------------------
// Laufzeit: die Hülle

function fakeFetch(response = { id: 'r-1' }, { status = 200 } = {}) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, init });
    return { ok: status < 400, status, json: async () => response };
  };
  f.calls = calls;
  return f;
}

test('createDraft legt über die Hülle einen Entwurf an (POST users/me/drafts, sonst nichts)', async () => {
  const f = fakeFetch({ id: 'r-42', message: { id: 'm' } });
  const id = await createDraft('kunde@example.org', 'Dein Paket', '<p>Hallo</p>', ['a@example.org'], { token: 'T', fetchImpl: f });
  assert.equal(id, 'r-42');
  assert.equal(f.calls.length, 1);
  const { url, init } = f.calls[0];
  assert.equal(url, 'https://gmail.googleapis.com/gmail/v1/users/me/drafts');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers.Authorization, 'Bearer T');
  const raw = JSON.parse(init.body).message.raw;
  const mime = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  assert.match(mime, /^To: kunde@example\.org\r\nCc: a@example\.org\r\n/);
});

test('createDraft meldet API-Fehler wie bisher', async () => {
  const f = fakeFetch({ error: { message: 'nope' } }, { status: 403 });
  await assert.rejects(createDraft('k@example.org', 'S', '<p>x</p>', undefined, { token: 'T', fetchImpl: f }), /Gmail API 403/);
});

const SEND_PATHS = [
  'messages/send', 'drafts/send', 'MESSAGES/SEND', 'drafts/send?alt=json', 'drafts%2Fsend', 'drafts%252Fsend',
  'messages/send/', 'settings/sendAs', 'settings/sendAs/x@example.org', 'drafts:send', 'drafts/r-1/../send',
  '../me/messages/send', '/upload/gmail/v1/users/me/messages/send', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
];

test('Hülle wirft bei jedem Versand-Pfad mit Klartext, bevor etwas ins Netz geht (auch dynamisch gebaut)', async () => {
  for (const path of [...SEND_PATHS, ['drafts', 'send'].join('/'), `messages/${'se' + 'nd'}`]) {
    const f = fakeFetch();
    await assert.rejects(gmailPost({ token: 'T', path, body: {}, fetchImpl: f }), (e) => {
      assert.ok(e instanceof GmailSendBlockedError, `${path}: ${e.message}`);
      assert.match(e.message, /Versand nur durch Test-Inhaber/);
      return true;
    }, path);
    assert.equal(f.calls.length, 0, `${path}: fetch wurde aufgerufen`);
  }
});

test('gmailGet sperrt Versand-Pfade ebenso', async () => {
  for (const path of ['messages/send', 'drafts/send', 'settings/sendAs']) {
    const f = fakeFetch();
    await assert.rejects(gmailGet({ token: 'T', mailbox: 'me', path, fetchImpl: f }), GmailSendBlockedError, path);
    assert.equal(f.calls.length, 0);
  }
});

test('Hülle schreibt nur Entwürfe: andere Pfade und Methoden werden abgelehnt', async () => {
  const f = fakeFetch();
  for (const path of ['messages', 'messages/import', 'messages/batchModify', 'threads/t1/modify', 'settings/forwardingAddresses', 'drafts/a/b']) {
    await assert.rejects(gmailPost({ token: 'T', path, body: {}, fetchImpl: f }), /nicht erlaubt/, path);
  }
  for (const method of ['DELETE', 'PATCH', 'GET']) {
    await assert.rejects(gmailPost({ token: 'T', path: 'drafts', method, body: {}, fetchImpl: f }), /nicht erlaubt/, method);
  }
  assert.equal(f.calls.length, 0);
});

test('Hülle lässt drafts anlegen (POST) und drafts/<id> ändern (PUT) durch, Postfach wird kodiert', async () => {
  const f = fakeFetch();
  await gmailPost({ token: 'T', mailbox: 'tracking@example.org', path: 'drafts', body: { a: 1 }, fetchImpl: f });
  await gmailPost({ token: 'T', path: 'drafts/r-123_ab', method: 'put', body: { b: 2 }, fetchImpl: f });
  assert.deepEqual(f.calls.map((c) => [c.init.method, c.url]), [
    ['POST', 'https://gmail.googleapis.com/gmail/v1/users/tracking%40example.org/drafts'],
    ['PUT', 'https://gmail.googleapis.com/gmail/v1/users/me/drafts/r-123_ab'],
  ]);
});

test('assertNoSend lässt die heutigen Lese- und Entwurfspfade durch', () => {
  for (const p of ['profile', 'messages', 'messages/18f2a', 'drafts', 'drafts/r-1', 'threads/abc', 'labels']) assert.equal(assertNoSend(p), p);
});
