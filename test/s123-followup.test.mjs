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
    'Neue Anmeldung bei Wise', 'Neues Gerät angemeldet', 'Nouvelle connexion à votre compte', 'Connexion depuis un nouvel appareil',
    // d multi-factor / two-step
    'Multi-Faktor-Authentifizierung aktiviert', 'Zweistufige Bestätigung', '2-step verification turned on',
    'Authentification à deux facteurs activée', 'Authentification multifacteur',
    // e Identität verifizieren
    'Bitte Identität verifizieren', 'Identität bestätigen', 'Verify your identity', 'Vérifiez votre identité', 'Merci de vérifier votre identité',
    // f security alert
    'Sicherheitshinweis zu Ihrem Konto', 'Alerte de sécurité', 'Votre code de vérification',
  ]) assert.ok(isSecurityMail({ from: 'x@y.example', subject }), subject);
  for (const subject of ['Bestellbestätigung #1042', 'Votre commande est expédiée', 'Neues Armagnac-Paket', 'Passwortgeschützte Datei']) {
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
