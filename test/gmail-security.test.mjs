// Sicherheitsmails mit dem konfigurierten Sperr-Label (im Test agent-no-read) liest kein Lesepfad von src/gmail.js.
// Prüfungen gegen die Dateien eines nutzenden Repos (seine Konfiguration, seine Aufrufer) gehören in dessen Tests.
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { configureGmailGuard, gmailGuardConfig, GmailBlockedError, gmailGet, listMessageIds, getMessage, getThreadMeta, assertBalancedQuery, labelKey, readPortalCodeMails, CODE_MAIL_WINDOW_MS } from '../src/gmail.js';

configureGmailGuard({ blockedLabel: 'agent-no-read' });
const CODE_MAIL_SENDERS = ['portal-a.example', 'portal-b.example'];

function fake({ labels = [{ id: 'INBOX', name: 'INBOX' }, { id: 'Label_7', name: 'Agent No Read' }], msgs = {} } = {}) {
  const log = [];
  const state = { labels };
  const fetchImpl = async (url) => {
    log.push(url);
    const u = new URL(url);
    const p = u.pathname.split('/').slice(5).join('/');
    const mid = decodeURIComponent(p.split('/')[1] ?? '');
    // `fields` entfernt labelIds wie bei Gmail (Partial response)
    const msgBody = () => (u.searchParams.get('fields') ? { id: mid, payload: { secret: 'INHALT' } } : { id: mid, labelIds: msgs[mid] ?? [], payload: { secret: 'INHALT' } });
    const body = p === 'labels' ? (state.labels === null ? {} : { labels: state.labels })
      : p === 'messages' ? { messages: Object.keys(msgs).map((id) => ({ id, threadId: 't1' })) }
        : /^messages\/[^/]+$/.test(p) ? msgBody()
          : /\/attachments\//.test(p) ? { data: 'eA' }
            : p.startsWith('threads/') ? { id: 't1', messages: Object.entries(msgs).map(([id, l]) => ({ id, labelIds: l })) } : {};
    return { ok: true, status: 200, json: async () => body };
  };
  return { fetchImpl, log, state };
}
const A = { token: 'tok', mailbox: 'me' };

test('Wächter-Konfiguration: einmalig, gleiche Werte erlaubt, andere werfen, ungültige abgelehnt', () => {
  assert.equal(gmailGuardConfig().blockedLabel, 'agent-no-read');
  assert.equal(configureGmailGuard({ blockedLabel: 'agent-no-read' }).blockedLabel, 'agent-no-read');
  assert.throws(() => configureGmailGuard({ blockedLabel: 'anderes-label' }), /schon anders konfiguriert/);
  for (const blockedLabel of [undefined, '', 'A B', 'x', 'a'.repeat(41), 'label:x']) assert.throws(() => configureGmailGuard({ blockedLabel }), /blockedLabel/, String(blockedLabel));
  assert.throws(() => configureGmailGuard({ blockedLabel: 'agent-no-read', sendBlockedReason: 'a\nb' }), /sendBlockedReason/);
});

test('jede Suche mit -label, Anfrage geklammert', async () => {
  const f = fake({ msgs: { m1: ['INBOX'] } });
  await listMessageIds({ ...A, q: 'from:a OR from:b', fetchImpl: f.fetchImpl });
  await gmailGet({ ...A, path: 'messages', params: {}, fetchImpl: f.fetchImpl });
  const qs = f.log.filter((u) => /\/messages\?/.test(u)).map((u) => new URL(u).searchParams.get('q'));
  assert.deepEqual(qs, ['(from:a OR from:b) -label:agent-no-read', '-label:agent-no-read']);
});

test('Mail, Verlauf und Anhang mit dem Label gesperrt, andere gehen durch', async () => {
  const f = fake({ msgs: { m1: ['INBOX'], m2: ['Label_7'] } });
  await assert.rejects(getMessage({ ...A, id: 'm2', format: 'full', fetchImpl: f.fetchImpl }), (e) => e instanceof GmailBlockedError && /Sicherheitsmail/.test(e.message));
  assert.equal((await getMessage({ ...A, id: 'm1', fetchImpl: f.fetchImpl })).id, 'm1');
  await assert.rejects(getThreadMeta({ ...A, threadId: 't1', fetchImpl: f.fetchImpl }), GmailBlockedError);
  await assert.rejects(gmailGet({ ...A, path: 'messages/m2/attachments/a1', fetchImpl: f.fetchImpl }), GmailBlockedError);
  assert.ok(!f.log.some((u) => /m2\/attachments/.test(u)), 'Anhang nie abgerufen');
  assert.deepEqual(await gmailGet({ ...A, path: 'messages/m1/attachments/a1', fetchImpl: f.fetchImpl }), { data: 'eA' });
});

test('Labels nicht lesbar → nichts gelesen; Label fehlt → Warnung, liest weiter', async () => {
  const kaputt = fake({ labels: null, msgs: { m1: [] } });
  await assert.rejects(getMessage({ ...A, id: 'm1', fetchImpl: kaputt.fetchImpl }), /nicht prüfbar, nichts gelesen/);
  assert.ok(!kaputt.log.some((u) => /messages\/m1/.test(u)));
  const ohne = fake({ labels: [{ id: 'INBOX', name: 'INBOX' }], msgs: { m1: [] } });
  const alt = console.warn; const w = [];
  console.warn = (m) => w.push(m);
  try { assert.equal((await getMessage({ ...A, mailbox: 'ohne-label@example.org', id: 'm1', fetchImpl: ohne.fetchImpl })).id, 'm1'); } finally { console.warn = alt; }
  assert.match(w[0], /WARNUNG Gmail: Label agent-no-read fehlt/);
});

test('fields entfernt die Prüfgrundlage nicht; Prüfung vor dem Inhaltsabruf', async () => {
  const f = fake({ msgs: { m2: ['Label_7'] } });
  await assert.rejects(gmailGet({ ...A, path: 'messages/m2', params: { format: 'full', fields: 'id,payload' }, fetchImpl: f.fetchImpl }), GmailBlockedError);
  assert.deepEqual(f.log.filter((u) => /messages\/m2/.test(u)).map((u) => new URL(u).searchParams.get('format')), ['minimal'], 'nur der Prüfabruf');
});

test('nur feste Lesepfade, kein ? im Pfad, keine Thread-Liste', async () => {
  const f = fake({ msgs: { m2: ['Label_7'] } });
  for (const path of ['messages?labelIds=Label_7', 'threads', 'messages/m2#x', 'history', 'drafts', 'messages/m2/modify']) {
    await assert.rejects(gmailGet({ ...A, path, fetchImpl: f.fetchImpl }), /nicht erlaubt|Versand/, path);
  }
});

test('„Label fehlt“ nur 20 s gemerkt; Cache je Token; alle Schreibweisen der Suche gesperrt', async () => {
  const f = fake({ labels: [{ id: 'INBOX', name: 'INBOX' }], msgs: { m2: ['Label_9'] } });
  const alt = console.warn; console.warn = () => {};
  mock.timers.enable({ apis: ['Date'], now: Date.now() });
  try {
    assert.equal((await getMessage({ ...A, mailbox: 'neu@example.org', id: 'm2', fetchImpl: f.fetchImpl })).id, 'm2');
    f.state.labels = [{ id: 'Label_9', name: 'agent-no-read' }];
    mock.timers.tick(21_000);
    await assert.rejects(getMessage({ ...A, mailbox: 'neu@example.org', id: 'm2', fetchImpl: f.fetchImpl }), GmailBlockedError, 'neu angelegtes Label wirkt nach höchstens 20 s');
  } finally { console.warn = alt; mock.timers.reset(); }
  const zwei = fake({ labels: [{ id: 'Label_A', name: 'Agent No Read' }, { id: 'Label_B', name: 'agent-no-read' }], msgs: { m3: ['Label_B'] } });
  await assert.rejects(getMessage({ ...A, mailbox: 'zwei@example.org', id: 'm3', fetchImpl: zwei.fetchImpl }), GmailBlockedError);
  const konten = fake({ labels: [{ id: 'Label_7', name: 'agent-no-read' }], msgs: { m4: ['Label_8'] } });
  await getMessage({ token: 'konto-a', mailbox: 'me', id: 'm4', fetchImpl: konten.fetchImpl });
  konten.state.labels = [{ id: 'Label_8', name: 'agent-no-read' }];
  await assert.rejects(getMessage({ token: 'konto-b', mailbox: 'me', id: 'm4', fetchImpl: konten.fetchImpl }), GmailBlockedError, 'Konto B nutzt nicht die Label-ID von Konto A');
});

test('Prüfabruf ohne passende ID oder mit kaputten Labels → nichts gelesen', async () => {
  const kaputt = async (url) => {
    const p = new URL(url).pathname.split('/').slice(5).join('/');
    return { ok: true, status: 200, json: async () => (p === 'labels' ? { labels: [{ id: 'L', name: 'agent-no-read' }] } : { id: 'm1', labelIds: 'x', payload: {} }) };
  };
  await assert.rejects(getMessage({ ...A, mailbox: 'k@example.org', id: 'm1', fetchImpl: kaputt }), /nicht lesbar; nichts gelesen/);
});

test('unausgeglichene Klammern oder Anführungszeichen in der Suche abgelehnt', async () => {
  for (const q of ['x) OR', '"abc', '{x', '(a', 'a)(', '{a}}', '"a) OR"', 'foo"bar) OR "', '"x) OR (label:agent-no-read"', 'subject:"a (b"']) assert.throws(() => assertBalancedQuery(q), /nicht ausgeglichen/, q);
  for (const q of ['from:(a OR b) -in:spam', 'has:attachment {from:a from:b}', 'subject:"a b"', 'from:("x y" OR z)', '', undefined]) assertBalancedQuery(q);
  const f = fake({ msgs: {} });
  await assert.rejects(listMessageIds({ ...A, q: 'x) OR', fetchImpl: f.fetchImpl }), /nicht ausgeglichen/);
  assert.ok(!f.log.some((u) => /\/messages\?/.test(u)));
});

test('Normalisierung wie die Gmail-Suche, IDs nur [A-Za-z0-9_-]', async () => {
  assert.equal(labelKey('Agent No Read'), 'agent-no-read');
  assert.notEqual(labelKey('agent_no_read'), 'agent-no-read');
  const f = fake({ msgs: { m1: [] } });
  for (const path of ['messages/.', 'messages/%2e', 'threads/.', 'messages/abc\\attachments\\x']) {
    await assert.rejects(gmailGet({ ...A, path, fetchImpl: f.fetchImpl }), /nicht erlaubt/, path);
  }
});

test('Ausnahme Code-Mails: nur fester Absender, nur 20 Minuten, gelabelte Code-Mail lesbar', async () => {
  const jetzt = Date.now();
  const mails = {
    a1: { from: 'Portal <noreply@login.portal-a.example>', t: jetzt - 60_000, labels: ['Label_7'] },   // passt, Sicherheitsmail
    a2: { from: 'Fremd <x@evil.example.org>', t: jetzt - 60_000, labels: ['Label_7'] },           // anderer Absender
    a3: { from: 'noreply@portal-a.example', t: jetzt - CODE_MAIL_WINDOW_MS - 60_000, labels: ['Label_7'] }, // zu alt
    a5: { from: 'a@evil.org, Portal <noreply@portal-a.example>', t: jetzt - 1000, labels: [] },          // mehrere Adressen
    a4: { from: 'Täuschung <noreply@portal-a.example.evil.org>', t: jetzt - 1000, labels: [] },        // Domain nur als Präfix
  };
  const log = [];
  const fetchImpl = async (url) => {
    log.push(url);
    const u = new URL(url);
    const p = u.pathname.split('/').slice(5).join('/');
    if (p === 'messages') return { ok: true, status: 200, json: async () => ({ messages: Object.keys(mails).map((id) => ({ id, threadId: 't' })) }) };
    const id = p.split('/')[1];
    const m = mails[id];
    return { ok: true, status: 200, json: async () => ({ id, internalDate: String(m.t), labelIds: m.labels, payload: { headers: [{ name: 'From', value: m.from }, { name: 'Subject', value: 'Code' }] } }) };
  };
  const r = await readPortalCodeMails({ token: 't', mailbox: 'me', senderDomain: 'portal-a.example', codeMailSenders: CODE_MAIL_SENDERS, fetchImpl });
  assert.deepEqual(r.messages.map((m) => m.id), ['a1']);
  const voll = log.filter((u) => new URL(u).searchParams.get('format') === 'full').map((u) => new URL(u).pathname.split('/').pop());
  assert.deepEqual(voll, ['a1'], 'nur die passende Mail geöffnet');
  assert.equal(new URL(log[0]).searchParams.get('q'), 'from:portal-a.example newer_than:1d');
  for (const bad of ['', 'example', 'a b.com', 'x.com OR y.com', 'evil.com) OR (x', 'accounts.google.com', 'google.com', 'co.uk', 'example.com']) {
    await assert.rejects(readPortalCodeMails({ token: 't', mailbox: 'me', senderDomain: bad, codeMailSenders: CODE_MAIL_SENDERS, fetchImpl }), /Absender-Domain/, bad);
  }
});

test('ohne Absenderliste des Aufrufers kein Abruf; Domain muss in der Liste stehen', async () => {
  const log = [];
  const fetchImpl = async (url) => { log.push(url); return { ok: true, status: 200, json: async () => ({ messages: [] }) }; };
  for (const liste of [undefined, [], [''], 'portal-a.example', [null]]) {
    await assert.rejects(readPortalCodeMails({ token: 't', mailbox: 'me', senderDomain: 'portal-a.example', codeMailSenders: liste, fetchImpl }), /codeMailSenders/, String(liste));
  }
  await assert.rejects(readPortalCodeMails({ token: 't', mailbox: 'me', senderDomain: 'portal-b.example', codeMailSenders: ['portal-a.example'], fetchImpl }), /steht nicht in codeMailSenders/);
  assert.equal(log.length, 0, 'nichts abgerufen');
  await readPortalCodeMails({ token: 't', mailbox: 'me', senderDomain: 'portal-a.example', codeMailSenders: ['Portal-A.example'], fetchImpl });
  assert.equal(log.length, 1);
});

test('Sperr-Label gelöscht und neu angelegt (neue ID) innerhalb des Caches: Mail trotzdem gesperrt', async () => {
  const f = fake({ labels: [{ id: 'INBOX', name: 'INBOX' }, { id: 'L_alt', name: 'agent-no-read' }], msgs: { m1: ['INBOX'], m2: ['L_neu'] } });
  assert.equal((await getMessage({ ...A, mailbox: 'neu-angelegt@example.org', id: 'm1', fetchImpl: f.fetchImpl })).id, 'm1');
  f.state.labels = [{ id: 'INBOX', name: 'INBOX' }, { id: 'L_neu', name: 'agent-no-read' }];
  await assert.rejects(getMessage({ ...A, mailbox: 'neu-angelegt@example.org', id: 'm2', format: 'full', fetchImpl: f.fetchImpl }), GmailBlockedError);
  assert.ok(!f.log.some((u) => /messages\/m2/.test(u) && new URL(u).searchParams.get('format') === 'full'), 'Inhalt nie abgerufen');
});

test('Label fehlte (Negativ-Cache) und wird gleich danach angelegt: unbekannte ID erzwingt frischen Stand', async () => {
  const warn = console.warn; console.warn = () => {};
  try {
    const f = fake({ labels: [{ id: 'INBOX', name: 'INBOX' }], msgs: { m1: ['INBOX'], m2: ['L_x'] } });
    await getMessage({ ...A, mailbox: 'spaet@example.org', id: 'm1', fetchImpl: f.fetchImpl });
    f.state.labels = [{ id: 'INBOX', name: 'INBOX' }, { id: 'L_x', name: 'Agent No Read' }];
    await assert.rejects(getMessage({ ...A, mailbox: 'spaet@example.org', id: 'm2', fetchImpl: f.fetchImpl }), GmailBlockedError);
  } finally { console.warn = warn; }
});

test('Netzfehler nennen nie die Fehlermeldung von fetch (sie kann den Authorization-Kopf enthalten)', async () => {
  const fetchImpl = async () => { throw new TypeError('Headers.append: "Bearer ya29.GEHEIM\nx" is an invalid header value.'); };
  await assert.rejects(gmailGet({ ...A, path: 'profile', fetchImpl }), (e) => !/GEHEIM/.test(e.message) && /nicht erreichbar/.test(e.message));
});

test('Label-ID, die auch der frische Stand nicht kennt: höchstens ein Neuabruf, dann gemerkt', async () => {
  const f = fake({ labels: [{ id: 'INBOX', name: 'INBOX' }, { id: 'Label_7', name: 'agent-no-read' }], msgs: { m1: ['INBOX', 'X_UNBEKANNT'], m3: ['X_UNBEKANNT'] } });
  await getMessage({ ...A, mailbox: 'unbekannt@example.org', id: 'm1', fetchImpl: f.fetchImpl });
  await getMessage({ ...A, mailbox: 'unbekannt@example.org', id: 'm3', fetchImpl: f.fetchImpl });
  assert.equal(f.log.filter((u) => new URL(u).pathname.endsWith('/labels')).length, 2, 'erster Stand + ein Neuabruf, danach gemerkt');
});
