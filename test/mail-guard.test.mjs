// Mail-Wächter (src/mail-guard.js, S114 „Mail-Wächter: nächtliche Prüfung und 2FA-Filter nachziehen“, Sascha 23.11.2026
// „go“): je Postfach (1) neue oder geänderte Filter, Weiterleitungen, Delegierungen, IMAP/POP gegen den gesicherten
// Stand, (2) Gesendete mit unbekanntem Client-Fingerabdruck, (3) Mails, die wie 2FA/Codes/Passwort-Links aussehen und
// das Sperr-Label nicht tragen. Nur lesend (GET), Meldung ohne Mailinhalt. Ohne Netz: Gmail ist eine Attrappe.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { configureGmailGuard } from '../src/gmail.js';
import { SECURITY_FILTERS } from '../src/gmail-setup.js';
import {
  diffSettings, formatNotification, maskSubject, scanMailbox, securityCandidate, sentFingerprint, settingsItems,
} from '../src/mail-guard.js';

configureGmailGuard({ blockedLabel: 'security-no-read', requireLabel: true });

const BOX = 'hello@example.org';
const H = (o) => Object.entries(o).map(([name, value]) => ({ name, value }));
const EM = H({ 'Message-ID': '<em1c2d3e4f-aaaa-bbbb@example.org>', 'User-Agent': 'eMClient/11.0.0.0', 'Content-Type': 'multipart/alternative; boundary="------=_MBC1E5F0A2-3B4C-5D6E-7F80-91A2B3C4D5E6"', To: 'Kunde <k@kunde.de>', Subject: 'Angebot', Date: 'Mon, 23 Nov 2026 10:00:00 +0100' });
const WEB = H({ 'Message-ID': '<CAMx7f=abc123@mail.gmail.com>', 'Content-Type': 'multipart/alternative; boundary="0000000000005f2a1b0623c4d5e6"', To: 'x@partner.fr', Subject: 'Re: Termin', Date: 'Mon, 23 Nov 2026 11:00:00 +0100' });
// so sähe eine über die API gesendete Mail aus, deren MIME ein Skript baut (buildMime: einteilig, ohne Client-Kopf)
const API = H({ 'Message-ID': '<CAMy8g=def456@mail.gmail.com>', 'Content-Type': 'text/html; charset="UTF-8"', To: 'opfer@fremd.example', Subject: 'Rechnung 4711 bitte zahlen', Date: 'Tue, 24 Nov 2026 03:00:00 +0100' });

test('Fingerabdruck: Client ohne Version, Message-ID-Host, Form der MIME-Grenze', () => {
  assert.equal(sentFingerprint(EM), 'ua:eMClient id@example.org b:------=_M#-#-#-#-#');
  assert.equal(sentFingerprint(WEB), 'ua:- id@mail.gmail.com b:#');
  assert.equal(sentFingerprint(API), 'ua:- id@mail.gmail.com b:-');
  assert.notEqual(sentFingerprint(API), sentFingerprint(WEB), 'einteilige Mail ohne Client-Kopf ist nicht Gmail im Browser');
  // Versand-Dienste mit wechselnden internen Hostnamen (hello@, Probelauf 24.11.): ein Abdruck, nicht einer je Server
  const a = H({ 'Message-ID': '<1.2@ip-10-2-179-78>', 'X-Mailer': 'lxo', 'Content-Type': 'multipart/mixed; boundary="----=_Part_1_2.3"' });
  const b = H({ 'Message-ID': '<4.5@ip-10-4-58-106>', 'X-Mailer': 'lxo', 'Content-Type': 'multipart/mixed; boundary="----=_Part_9_8.7"' });
  assert.equal(sentFingerprint(a), sentFingerprint(b));
});

test('Betreff gekürzt, Ziffernfolgen maskiert (Codes stehen oft im Betreff)', () => {
  assert.equal(maskSubject('Dein Code lautet 482913'), 'Dein Code lautet ••••');
  assert.equal(maskSubject('G-123456 is your Google verification code'), 'G-•••• is your Google verificati…');
  assert.equal(maskSubject('Bestellung 12'), 'Bestellung 12', 'kurze Zahlen bleiben');
  assert.equal(maskSubject('a\r\nb'), 'a b');
});

test('2FA-Kandidaten: Codes, Passwort-Links, Anmelde-Bestätigung; Bestellbestätigung und Rabattcode nicht', () => {
  for (const s of ['Your authentication code', 'Ihr Zugangscode: 123456', 'Confirm your email address', 'Neue Anmeldung bei Konto X',
    'Kennwort zurücksetzen', 'Security alert for your account', 'Bestätige Deine E-Mail-Adresse', 'Your sign-in link', '847261 ist Dein Code',
    'Verify your login', 'Ihre TAN für den Login']) assert.ok(securityCandidate({ from: 'a@b.de', subject: s }), s);
  for (const s of ['Bestellbestätigung #1042', 'Dein Rabattcode für den Black Friday', 'Auftragsbestätigung 2026-11-24', 'Re: Termin',
    'Versandbestätigung', 'Newsletter: neue Armagnacs', 'Re: [anthropics/claude-code] Model picker (Issue #12345)']) assert.equal(securityCandidate({ from: 'a@b.de', subject: s }), null, s);
});

test('Einstellungen: neuer Weiterleitungs-Filter und entfernter Sicherheitsfilter werden gemeldet, mit Ziel-Domain', () => {
  const vorher = settingsItems({
    labels: [{ id: 'Label_1', name: 'security-no-read' }],
    filters: [{ id: 'F1', criteria: SECURITY_FILTERS[0].criteria, action: { addLabelIds: ['Label_1'] } }],
    forwardingAddresses: [], autoForwarding: { enabled: false }, imap: { enabled: true }, pop: { accessWindow: 'disabled' }, delegates: [],
  });
  const nachher = settingsItems({
    labels: [{ id: 'Label_1', name: 'security-no-read' }],
    filters: [{ id: 'F9', criteria: { from: 'bank.de' }, action: { forward: 'dieb@evil.example', removeLabelIds: ['INBOX'] } }],
    forwardingAddresses: [{ forwardingEmail: 'dieb@evil.example', verificationStatus: 'accepted' }],
    autoForwarding: { enabled: false }, imap: { enabled: true }, pop: { accessWindow: 'disabled' }, delegates: [],
  });
  const d = diffSettings(vorher, nachher);
  const texte = d.map((x) => `${x.change} ${x.summary}`);
  assert.ok(texte.some((t) => /^neu Filter .*Weiterleitung an @evil\.example.*Posteingang überspringen/.test(t)), texte.join('\n'));
  assert.ok(texte.some((t) => /^entfernt Sicherheitsfilter/.test(t)), texte.join('\n'));
  assert.ok(texte.some((t) => /^neu Weiterleitungsadresse @evil\.example \(accepted\)/.test(t)), texte.join('\n'));
  assert.ok(!texte.join(' ').includes('dieb@'), 'nur Domain, keine volle Adresse');
  assert.deepEqual(diffSettings(nachher, nachher), []);
});

// ---------- ein Postfach gegen eine Gmail-Attrappe ----------
function gmail({ sent = [], inbox = [], filters = null, forwarding = [] } = {}) {
  const log = [];
  const msgs = new Map([...sent, ...inbox].map((m) => [m.id, m]));
  const f = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? 'GET';
    const p = decodeURIComponent(u.pathname).replace(`/gmail/v1/users/${BOX}/`, '');
    log.push({ method, p, q: u.searchParams.get('q'), format: u.searchParams.get('format') });
    const ok = (b) => ({ ok: true, status: 200, json: async () => b, text: async () => JSON.stringify(b) });
    if (method !== 'GET') return { ok: false, status: 405, json: async () => ({}) };
    if (p === 'labels') return ok({ labels: [{ id: 'INBOX', name: 'INBOX' }, { id: 'SENT', name: 'SENT' }, { id: 'Label_1', name: 'security-no-read' }] });
    if (p === 'settings/filters') return ok({ filter: filters ?? SECURITY_FILTERS.map((s, i) => ({ id: `S${i}`, criteria: s.criteria, action: { addLabelIds: ['Label_1'] } })) });
    if (p === 'settings/forwardingAddresses') return ok({ forwardingAddresses: forwarding });
    if (p === 'settings/autoForwarding') return ok({ enabled: false });
    if (p === 'settings/imap') return ok({ enabled: true });
    if (p === 'settings/pop') return ok({ accessWindow: 'disabled' });
    if (p === 'settings/delegates') return ok({});
    if (p === 'messages') {
      const q = u.searchParams.get('q');
      assert.match(q, /-label:security-no-read/, 'jede Suche schließt das Sperr-Label aus');
      const pool = /(^|[\s(])in:sent/.test(q) ? sent : inbox;
      return ok({ messages: pool.map((m) => ({ id: m.id, threadId: m.id })) });
    }
    const m = /^messages\/([^/]+)$/.exec(p);
    if (m && msgs.has(m[1])) { const x = msgs.get(m[1]); return ok({ id: x.id, labelIds: x.labelIds ?? ['SENT'], internalDate: String(x.at ?? Date.parse('2026-11-24T02:00:00Z')), snippet: 'GEHEIM 991122', payload: { headers: x.headers } }); }
    return { ok: false, status: 404, json: async () => ({ error: { message: 'nicht da' } }) };
  };
  f.log = log;
  return f;
}
const NOW = Date.parse('2026-11-24T05:00:00Z');

test('erster Lauf legt den Grundstand an und meldet nichts; zweiter Lauf meldet Neues; nur GET', async () => {
  const f1 = gmail({ sent: [{ id: 'm1', headers: EM }, { id: 'm2', headers: WEB }] });
  const r1 = await scanMailbox({ token: 'T', mailbox: BOX, state: null, now: NOW - 86_400_000, fetchImpl: f1 });
  assert.equal(r1.baseline, true);
  assert.deepEqual(r1.findings, []);
  assert.deepEqual(Object.keys(r1.state.sent.known).sort(), ['ua:- id@mail.gmail.com b:#', 'ua:eMClient id@example.org b:------=_M#-#-#-#-#']);

  const f2 = gmail({
    sent: [{ id: 'm3', headers: EM }, { id: 'm4', headers: API }],
    inbox: [
      { id: 'i1', labelIds: ['INBOX'], headers: H({ From: 'Konto X <noreply@login.konto-x.example>', Subject: 'Your authentication code 551234', Date: 'x' }) },
      { id: 'i2', labelIds: ['INBOX'], headers: H({ From: 'Shop <shop@laden.example>', Subject: 'Bestellbestätigung #1042', Date: 'x' }) },
      { id: 'i3', labelIds: ['INBOX'], headers: H({ From: 'Bank <info@bank.example>', Subject: 'Ihr Bestätigungscode 445566', Date: 'x' }) },
    ],
    filters: [...SECURITY_FILTERS.map((s, i) => ({ id: `S${i}`, criteria: s.criteria, action: { addLabelIds: ['Label_1'] } })),
      { id: 'F9', criteria: { from: 'bank.example' }, action: { forward: 'dieb@evil.example' } }],
  });
  const r2 = await scanMailbox({ token: 'T', mailbox: BOX, state: r1.state, now: NOW, fetchImpl: f2 });
  assert.ok(f2.log.every((c) => c.method === 'GET'), 'nur lesend');
  const arten = r2.findings.map((x) => `${x.kind}:${x.domain ?? ''}`).sort();
  assert.deepEqual(arten, ['security-list:bank.example', 'security:konto-x.example', 'sent:fremd.example', 'settings:evil.example']);
  const sent = r2.findings.find((x) => x.kind === 'sent');
  assert.equal(sent.subject, 'Rechnung •••• bitte zahlen');
  assert.ok(!JSON.stringify(r2.findings).includes('GEHEIM') && !JSON.stringify(r2.findings).includes('551234'), 'kein Auszug, kein Code');
  // unbekannter Fingerabdruck wird NICHT gelernt: die nächste API-Mail meldet wieder
  assert.equal(r2.state.sent.known[sentFingerprint(API)], undefined);
  // dieselben Mails melden nicht doppelt
  const r3 = await scanMailbox({ token: 'T', mailbox: BOX, state: r2.state, now: NOW + 60_000, fetchImpl: f2 });
  assert.deepEqual(r3.findings, []);
});

test('fehlender Sicherheitsfilter wird jede Nacht gemeldet (Einrichtung, nicht Änderung)', async () => {
  const f = gmail({ filters: [] });
  const r1 = await scanMailbox({ token: 'T', mailbox: BOX, state: null, now: NOW, fetchImpl: f });
  assert.deepEqual(r1.findings.map((x) => `${x.kind}:${x.detail}`), ['setup:fehlt filter-betreff, filter-absender']);
  const r2 = await scanMailbox({ token: 'T', mailbox: BOX, state: r1.state, now: NOW + 86_400_000, fetchImpl: f });
  assert.equal(r2.findings.filter((x) => x.kind === 'setup').length, 1);
});

test('Meldung: Postfach, Domain, Datum, Betreff gekürzt; nichts bei keinem Befund; laut bei Filter/Gesendet', () => {
  assert.equal(formatNotification([{ mailbox: BOX, findings: [] }]), null);
  const n = formatNotification([{ mailbox: BOX, findings: [
    { kind: 'sent', domain: 'fremd.example', date: '24.11. 04:00', subject: 'Rechnung •••• bitte zahlen', detail: 'ua:- id@mail.gmail.com b:-' },
    { kind: 'security', domain: 'konto-x.example', date: '24.11. 03:00', subject: 'Your authentication code ••••' },
  ] }]);
  assert.equal(n.priority, '4');
  assert.match(n.title, /Mail-Wächter: 2 Befunde/);
  assert.match(n.body, /hello@: gesendet .*24\.11\. 04:00 an @fremd\.example „Rechnung •••• bitte zahlen“/);
  assert.match(n.body, /hello@: 2FA ohne Label .*@konto-x\.example/);
  const leise = formatNotification([{ mailbox: BOX, findings: [{ kind: 'security', domain: 'x.example', date: '1.1.', subject: 's' }] }]);
  assert.equal(leise.priority, '3');
  const viele = formatNotification([{ mailbox: BOX, findings: Array.from({ length: 30 }, (_, i) => ({ kind: 'security', domain: `d${i}.example`, date: '1.1.', subject: 's' })) }]);
  assert.ok(viele.body.split('\n').length <= 16 && /\+15 weitere/.test(viele.body), viele.body);
});

test('Wächter-Modul ist nur lesend: keine schreibende Methode, keine Schreibfunktion, kein direkter API-Aufruf', () => {
  const src = readFileSync(resolve(import.meta.dirname, '../src/mail-guard.js'), 'utf8');
  for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.ok(!new RegExp(`['"\`]${m}['"\`]`).test(src), m);
  for (const w of ['createDraft', 'createCheckedDraft', 'gmailPost', 'applySecurityLabel', 'readPortalCodeMails']) assert.ok(!new RegExp(`\\b${w}\\b`).test(src), w);
  assert.ok(!/googleapis\.com/.test(src));
});

// ---------- Befehl mail-guard (src/mail-guard-cli.js) ----------
import { existsSync, readdirSync, statSync } from 'node:fs';
import { tmpDir } from './helpers/tmpdir.mjs';
import { run } from '../src/mail-guard-cli.js';

function mitNtfy(gm, { ntfyStatus = 200 } = {}) {
  const posts = [];
  const f = async (url, init = {}) => {
    if (String(url).startsWith('https://ntfy.example/')) { posts.push({ url: String(url), method: init.method, body: init.body }); return { ok: ntfyStatus < 400, status: ntfyStatus }; }
    return gm(url, init);
  };
  f.posts = posts; f.gm = gm;
  return f;
}
const ARGS = (dir, ...x) => ['check', '--key', '/nirgends/sa.json', '--label', 'security-no-read', '--mailbox', BOX, '--state-dir', dir, ...x];
const deps = (fetchImpl, extra = {}) => ({ fetchImpl, getToken: async () => 'T', env: { MAIL_GUARD_NTFY_URL: 'https://ntfy.example/topic' }, log: () => {}, err: () => {}, now: NOW, ...extra });

test('check: Grundstand ohne Meldung, Zustand 600; dann Befund → genau eine ntfy-Meldung ohne Inhalt, dann gespeichert', async (t) => {
  const dir = tmpDir('mail-guard-', t);
  const f1 = mitNtfy(gmail({ sent: [{ id: 'm1', headers: EM }] }));
  assert.equal(await run(ARGS(dir), deps(f1)), 0);
  assert.equal(f1.posts.length, 0);
  const datei = join(dir, readdirSync(dir)[0]);
  assert.equal(statSync(datei).mode & 0o777, 0o600);

  const f2 = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }));
  assert.equal(await run(ARGS(dir), deps(f2, { now: NOW + 86_400_000 })), 0);
  assert.equal(f2.posts.length, 1);
  const u = new URL(f2.posts[0].url);
  assert.equal(u.searchParams.get('title'), 'Mail-Wächter: 1 Befund');
  assert.equal(u.searchParams.get('priority'), '4');
  assert.match(f2.posts[0].body, /gesendet von unbekanntem Client .* an @fremd\.example „Rechnung •••• bitte zahlen“/);
  assert.ok(!f2.posts[0].body.includes('GEHEIM') && !f2.posts[0].body.includes('opfer@'));
  assert.ok(f2.gm.log.every((c) => c.method === 'GET'), 'Gmail nur lesend');
  // gespeichert: derselbe Lauf noch einmal meldet nichts
  const f3 = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }));
  assert.equal(await run(ARGS(dir), deps(f3, { now: NOW + 86_460_000 })), 0);
  assert.equal(f3.posts.length, 0);
});

test('check: Meldung scheitert → Exit 1, Zustand bleibt (nächster Lauf meldet erneut); Dry-Run meldet und speichert nichts', async (t) => {
  const dir = tmpDir('mail-guard-', t);
  await run(ARGS(dir), deps(mitNtfy(gmail({ sent: [{ id: 'm1', headers: EM }] }))));
  const vorher = readFileSync(join(dir, readdirSync(dir)[0]), 'utf8');
  const kaputt = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }), { ntfyStatus: 500 });
  assert.equal(await run(ARGS(dir), deps(kaputt, { now: NOW + 86_400_000 })), 1);
  assert.equal(readFileSync(join(dir, readdirSync(dir)[0]), 'utf8'), vorher);
  const ohneUrl = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }));
  assert.equal(await run(ARGS(dir), deps(ohneUrl, { now: NOW + 86_400_000, env: {} })), 1, 'ohne ntfy-Ziel nicht still weiter');
  assert.equal(readFileSync(join(dir, readdirSync(dir)[0]), 'utf8'), vorher);
  const dry = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }));
  const out = [];
  assert.equal(await run(ARGS(dir, '--dry-run'), deps(dry, { now: NOW + 86_400_000, log: (s) => out.push(s) })), 0);
  assert.equal(dry.posts.length, 0);
  assert.equal(readFileSync(join(dir, readdirSync(dir)[0]), 'utf8'), vorher);
  assert.match(out.join('\n'), /Mail-Wächter: 1 Befund/);
});

test('check: nicht lesbares Postfach → Exit 3, kein Zustand dafür; accept nimmt einen Abdruck an', async (t) => {
  const dir = tmpDir('mail-guard-', t);
  const tot = mitNtfy(async () => ({ ok: false, status: 403, json: async () => ({ error: { message: 'Delegation denied' } }), text: async () => '{}' }));
  assert.equal(await run(ARGS(dir), deps(tot)), 3);
  assert.equal(existsSync(dir) ? readdirSync(dir).length : 0, 0);
  await run(ARGS(dir), deps(mitNtfy(gmail({ sent: [{ id: 'm1', headers: EM }] }))));
  assert.equal(await run(['accept', '--mailbox', BOX, '--fingerprint', sentFingerprint(API), '--state-dir', dir], deps(null)), 0);
  const f = mitNtfy(gmail({ sent: [{ id: 'm4', headers: API }] }));
  assert.equal(await run(ARGS(dir), deps(f, { now: NOW + 86_400_000 })), 0);
  assert.equal(f.posts.length, 0, 'angenommener Abdruck meldet nicht mehr');
});

test('Befehl: einziger schreibender Aufruf ist die ntfy-Meldung; keine Schreibfunktion aus gmail/gmail-setup', () => {
  const src = readFileSync(resolve(import.meta.dirname, '../src/mail-guard-cli.js'), 'utf8');
  assert.equal((src.match(/method: 'POST'/g) ?? []).length, 1);
  assert.match(src, /async function notify\(url, n, fetchImpl = fetch\) \{[\s\S]*?method: 'POST'/);
  for (const w of ['createDraft', 'createCheckedDraft', 'gmailPost', 'applySecurityLabel', 'readPortalCodeMails', 'draftMail']) assert.ok(!new RegExp(`\\b${w}\\b`).test(src), w);
  for (const m of ['PUT', 'PATCH', 'DELETE']) assert.ok(!new RegExp(`['"\`]${m}['"\`]`).test(src), m);
});
