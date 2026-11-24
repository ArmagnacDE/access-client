// S123 (Mail-Weg Nacharbeiten, 24.11.2026): Merkmal-Liste DE/EN/FR (Board A782 a), Grundstand der Weiterleitungen
// (A789 b, A793 a), Umlaute im To-Kopf (RFC 2047), lesbarer Fehler bei Weiterleitung des Token-Endpunkts. Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { SECURITY_SUBJECTS, SUBJECT_QUERY, isSecurityMail } from '../src/security-mail.js';
import { diffSettings, settingsItems } from '../src/mail-guard.js';
import { buildDraftMime, buildMime } from '../src/gmail.js';
import { getDelegatedToken } from '../src/google-auth.js';
import { tmpDir } from './helpers/tmpdir.mjs';

test('Merkmal-Liste: alle Arten aus A782 a auch in Varianten und auf Französisch', () => {
  for (const subject of [
    // a verify email
    'Please verify email address', 'Confirm your email for Wispr', 'Bitte E-Mail-Adresse bestätigen', 'Bestätige Deine E-Mail-Adresse',
    'Bitte bestätigen Sie Ihre E-Mail-Adresse', 'Vérifiez votre adresse e-mail', 'Confirmez votre adresse e-mail',
    // b neues Passwort
    'Your new password', 'Votre nouveau mot de passe', 'Réinitialiser votre mot de passe', 'Mot de passe oublié ?',
    // c new login / device
    'Neues Gerät angemeldet', 'Nouvelle connexion à votre compte', 'Connexion depuis un nouvel appareil',
    // d multi-factor / two-step
    'Multi-Faktor-Authentifizierung aktiviert', 'Zweistufige Verifizierung aktiviert', '2-step verification turned on',
    'Authentification à deux facteurs activée', 'Authentification multifacteur',
    // e Identität verifizieren
    'Bitte Identität verifizieren', 'Identität bestätigen', 'Verify your identity', 'Vérifiez votre identité',
    // f security alert
    'Alerte de sécurité', 'Votre code de vérification',
  ]) assert.ok(isSecurityMail({ from: 'x@y.example', subject }), subject);
  // Geschäftsmails bleiben lesbar (Codex S123 #1)
  for (const subject of ['Bestellbestätigung #1042', 'Votre commande est expédiée', 'Neues Armagnac-Paket', 'Passwortgeschützte Datei',
    'Confirmez votre adresse de livraison pour votre commande', 'Vérifiez votre adresse de facturation', 'Liefertermin für Ihr neues Gerät',
    'Votre nouvel appareil est expédié', 'Zweistufige Destillation im Alambic', 'Sicherheitshinweis zum Produkt (GPSR)',
    'Neue Anmeldung zur Verkostung', 'Neues Gerät für das Lager', 'Neue Anmeldung bei unserer Verkostung', 'Nouvelle connexion ferroviaire Paris Bordeaux',
    'Les deux facteurs qui font un grand Armagnac', '2 step payment plan']) {
    assert.equal(isSecurityMail({ from: 'x@y.example', subject }), false, subject);
  }
  assert.ok(SUBJECT_QUERY.length < 1400, `Gmail-Filter bleibt unter der Längengrenze (${SUBJECT_QUERY.length})`);
  assert.equal(new Set(SECURITY_SUBJECTS.map((s) => s.toLowerCase())).size, SECURITY_SUBJECTS.length, 'keine Doppel');
});

const BASIS = { labels: [], filters: [], imap: { enabled: true }, pop: { accessWindow: 'disabled' }, delegates: [] };
const LEX = { forwardingEmail: 'armagnac@inbox.lexware.email', verificationStatus: 'accepted' };
const INV = { forwardingEmail: 'x@invoicefetcher.email', verificationStatus: 'pending' };
const stand = (forwardingAddresses, autoForwarding = { enabled: false }) => settingsItems({ ...BASIS, forwardingAddresses, autoForwarding }, { label: 'security-no-read' });
const texte = (a, b) => diffSettings(a, b).map((x) => `${x.change} ${x.summary}`);

test('Weiterleitungen: Grundstand mail@ (Lexware, invoicefetcher) still; Alarm nur bei neuer Adresse oder Einschalten', () => {
  const grund = stand([LEX, INV]);
  assert.deepEqual(texte(grund, stand([LEX, { ...INV, verificationStatus: 'accepted' }])), [], 'Statuswechsel ist kein Alarm');
  assert.deepEqual(texte(grund, stand([LEX])), [], 'Entfernen ist kein Alarm');
  assert.deepEqual(texte(grund, stand([LEX, INV, { forwardingEmail: 'dieb@evil.example', verificationStatus: 'pending' }])),
    ['neu Weiterleitungsadresse @evil.example (pending)']);
  assert.deepEqual(texte(grund, stand([LEX, INV], { enabled: true, emailAddress: LEX.forwardingEmail, disposition: 'leaveInInbox' })),
    ['neu Automatische Weiterleitung an @lexware.email (leaveInInbox)']);
  const an = stand([LEX, INV], { enabled: true, emailAddress: LEX.forwardingEmail, disposition: 'leaveInInbox' });
  assert.deepEqual(texte(an, grund), [], 'Ausschalten ist kein Alarm');
  assert.deepEqual(texte(an, stand([LEX, INV], { enabled: true, emailAddress: INV.forwardingEmail, disposition: 'trash' })),
    ['neu Automatische Weiterleitung an @invoicefetcher.email (trash)'], 'neues Ziel ist Alarm');
  // ein Filter mit Weiterleitung bleibt ein Alarm (wie bisher)
  const mitFilter = settingsItems({ ...BASIS, forwardingAddresses: [LEX, INV], autoForwarding: { enabled: false },
    filters: [{ id: 'F1', criteria: { from: 'lexoffice.de' }, action: { forward: LEX.forwardingEmail } }] }, { label: 'security-no-read' });
  assert.deepEqual(texte(grund, mitFilter), ['neu Filter (Kriterien from; Weiterleitung an @lexware.email)']);
});

const kopf = (mime, name) => mime.split('\r\n\r\n')[0].split('\r\n').find((z) => z.startsWith(`${name}: `));
test('To und Cc: Anzeigenamen mit Umlauten nach RFC 2047, Adresse bleibt lesbar', () => {
  const m = buildDraftMime({ to: 'Jörg Müller <jm@example.de>, plain@example.org', cc: ['"Doe, Jäne" <jd@example.fr>'], subject: 'x', text: 'y' });
  const b = (s) => `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
  assert.equal(kopf(m, 'To'), `To: ${b('Jörg Müller')} <jm@example.de>, plain@example.org`);
  assert.equal(kopf(m, 'Cc'), `Cc: ${b('Doe, Jäne')} <jd@example.fr>`);
  assert.equal(kopf(buildDraftMime({ to: 'Jane Doe <j@x.de>', subject: 'x', text: 'y' }), 'To'), 'To: Jane Doe <j@x.de>', 'ASCII unverändert');
  assert.equal(kopf(buildMime('Zoë <z@x.de>', 's', '<p>x</p>'), 'To'), `To: ${b('Zoë')} <z@x.de>`);
  // maskierte Anführungszeichen trennen nicht (Codex S123 #2)
  assert.equal(kopf(buildDraftMime({ to: '"Jörg \\"Sales, DACH\\"" <jm@example.de>, b@x.de', subject: 'x', text: 'y' }), 'To'), `To: ${b('Jörg "Sales, DACH"')} <jm@example.de>, b@x.de`);
});

test('Token-Abruf: keine Weiterleitung folgen, Fehler lesbar', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const datei = path.join(tmpDir('redir-'), 'sa.json');
  writeFileSync(datei, JSON.stringify({ client_email: 'a@b.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  const opts = [];
  const fetchImpl = async (url, o) => { opts.push(o); throw Object.assign(new TypeError('fetch failed'), { cause: new Error('unexpected redirect') }); };
  await assert.rejects(getDelegatedToken({ datei, sub: 'mail@x.de', scopes: ['s1'], fetchImpl }), /Token-Endpunkt leitet weiter/);
  assert.equal(opts[0].redirect, 'error');
});

// A800 a (Sascha 24.11.2026, Zusatz zu S123): mail-jobs kann Abwesenheitsnotizen setzen (erreichen Kunden); der
// Wächter meldet eine neue oder geänderte. Senden-als/Reply-To: Tests weiter unten (readAbsender).
const MIT = (vacation) => settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false }, vacation }, { label: 'security-no-read' });
test('Abwesenheitsnotiz: Alarm bei neu/geändert, still bei aus, ohne Inhalt im Zustand; alter Zustand lernt still', () => {
  const grund = MIT({ enableAutoReply: false });
  const an = MIT({ enableAutoReply: true, responseSubject: 'Bin weg bis 123456', responseBodyPlainText: 'GEHEIMER TEXT', restrictToContacts: false });
  assert.deepEqual(texte(grund, an).map((t) => t.replace(/„.*“/, '„…“')), ['neu Abwesenheitsnotiz an (an alle, Betreff „…“)']);
  assert.ok(!JSON.stringify(an).includes('GEHEIMER') && !JSON.stringify(an).includes('123456'), 'kein Text, keine Ziffern im Zustand');
  const geaendert = MIT({ enableAutoReply: true, responseSubject: 'Bin weg bis 123456', responseBodyPlainText: 'anderer Text', restrictToContacts: false });
  assert.equal(texte(an, geaendert).length, 1, 'geänderter Text ist ein Alarm');
  assert.deepEqual(texte(an, grund), [], 'Ausschalten ist still');
  assert.match(texte(grund, MIT({ enableAutoReply: true, restrictToDomain: true, responseSubject: 'x' }))[0], /nur Domain/);
  // Zustand aus v1.4.0 ohne diesen Bereich: einmal still lernen, kein Fehlalarm beim Update
  const alt = settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false } }, { label: 'security-no-read' });
  assert.deepEqual(texte(alt, an), []);
});

// A800 a („Bei go: Der Mail-Wächter meldet auch … Senden-als und Reply-To“; Entscheidung Orchestrator 24.11. a):
// EINE Leseausnahme zur Versand-Sperre, fest verdrahtet: GET genau users/<u>/settings/sendAs (Liste).
import { readAbsender } from '../src/gmail-setup.js';
import { assertNoSend, gmailGet, GmailSendBlockedError } from '../src/gmail.js';
test('Absender-Liste: nur GET genau auf settings/sendAs, ohne Unterpfad; alles andere bleibt gesperrt', async () => {
  const calls = [];
  const f = async (url, init = {}) => { calls.push({ url, method: init.method ?? 'GET', body: init.body }); return { ok: true, status: 200, text: async () => JSON.stringify({ sendAs: [{ sendAsEmail: 'mail@x.example', isPrimary: true, replyToAddress: 'r@y.example' }] }) }; };
  const l = await readAbsender({ token: 'T', mailbox: 'mail@x.example', fetchImpl: f, method: 'POST', path: 'settings/sendAs/x/verify' });
  assert.deepEqual(l, [{ email: 'mail@x.example', replyTo: 'r@y.example' }]);
  assert.deepEqual(calls, [{ url: 'https://gmail.googleapis.com/gmail/v1/users/mail%40x.example/settings/sendAs', method: 'GET', body: undefined }]);
  for (const p of ['settings/sendAs', 'settings/sendAs/a@b.de', 'settings/sendAs/a@b.de/verify', 'settings%2FsendAs', 'settings/SENDAS']) {
    assert.throws(() => assertNoSend(p), GmailSendBlockedError, p);
  }
  await assert.rejects(gmailGet({ token: 'T', mailbox: 'mail@x.example', path: 'settings/sendAs', fetchImpl: f }), GmailSendBlockedError);
  await assert.rejects(readAbsender({ token: 'T', mailbox: 'x/../y@x.example', fetchImpl: f }), /ungültig/);
  // kaputte Antwort ist ein Fehler, keine leere Liste (reviewer S123 B2)
  for (const body of ['', '{}', '{"sendAs":"x"}', '{"sendAs":[]}', '{"sendAs":[{}]}']) {
    await assert.rejects(readAbsender({ token: 'T', mailbox: 'mail@x.example', fetchImpl: async () => ({ ok: true, status: 200, text: async () => body }) }), /unvollständig/, body);
  }
});
test('Senden-als und Reply-To: Alarm bei neu, still bei entfernt; Signatur ändert nichts', () => {
  const S = (absender) => settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false }, absender }, { label: 'security-no-read' });
  const grund = S([{ email: 'mail@x.example', replyTo: '' }]);
  assert.deepEqual(texte(grund, S([{ email: 'mail@x.example', replyTo: '' }, { email: 'info@fremd.example', replyTo: '' }])), ['neu Senden als @fremd.example']);
  assert.deepEqual(texte(grund, S([{ email: 'mail@x.example', replyTo: 'dieb@evil.example' }])), ['neu Senden als @x.example (Reply-To @evil.example)']);
  assert.deepEqual(texte(S([{ email: 'mail@x.example', replyTo: '' }, { email: 'a@b.example', replyTo: '' }]), grund), []);
  const alt = settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false } }, { label: 'security-no-read' });
  assert.deepEqual(texte(alt, grund), [], 'älterer Zustand ohne den Bereich lernt still');
});

test('Update von v1.4.0: bekannte Weiterleitungsadressen im alten Schlüssel-Format melden nichts', async () => {
  const { createHash } = await import('node:crypto');
  const h = (x) => createHash('sha256').update(x).digest('hex').slice(0, 16);
  const neu = stand([LEX, INV]);
  const alt = Object.fromEntries(Object.entries(neu).filter(([k]) => !k.startsWith('forward:') && k !== 'format:2'));
  alt[`forward:${h(`${LEX.forwardingEmail}|accepted`)}`] = { summary: 'Weiterleitungsadresse @lexware.email (accepted)', domain: 'lexware.email' };
  alt[`forward:${h(`${INV.forwardingEmail}|pending`)}`] = { summary: 'Weiterleitungsadresse @invoicefetcher.email (pending)', domain: 'invoicefetcher.email' };
  assert.deepEqual(texte(alt, neu), []);
  assert.deepEqual(texte(neu, stand([LEX, INV, { forwardingEmail: 'neu@evil.example', verificationStatus: 'pending' }])), ['neu Weiterleitungsadresse @evil.example (pending)'], 'ab Format 2 wieder Alarm');
});

test('Update: still übernommene Bereiche stehen im Log (learnedSilently)', async () => {
  const { learnedSilently } = await import('../src/mail-guard.js');
  const alt = settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false } }, { label: 'security-no-read' });
  const neu = settingsItems({ ...BASIS, forwardingAddresses: [], autoForwarding: { enabled: false }, vacation: { enableAutoReply: true, responseSubject: 'x' }, absender: [{ email: 'mail@x.example', replyTo: 'r@evil.example' }] }, { label: 'security-no-read' });
  assert.deepEqual(learnedSilently(alt, neu).map((v) => v.summary).sort(), ['Abwesenheitsnotiz an (an alle, Betreff „x“)', 'Senden als @x.example (Reply-To @evil.example)']);
  assert.deepEqual(learnedSilently(neu, neu), []);
});
