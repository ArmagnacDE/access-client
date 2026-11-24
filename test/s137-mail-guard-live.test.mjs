// S137 (Mail-Wächter-Job live, 24.11.2026): Folgearbeit aus S123. „two-step“ allein traf „Two-step distillation“;
// Weiterleitungen des Token-Endpunkts auch auf den übrigen Token-Wegen lesbar abgebrochen. Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { FILTER_QUERY_MAX, SECURITY_SUBJECTS, SUBJECT_QUERIES, SUBJECT_QUERY, isSecurityMail } from '../src/security-mail.js';
import { getAccessTokenFromFile, grantedScopesOf } from '../src/google-auth.js';
import { tmpDir } from './helpers/tmpdir.mjs';

test('two-step: nur mit Anmelde-Bezug (authentication; 2-Step Verification steht schon drin), nicht Destillation oder Zahlungsplan', () => {
  for (const subject of ['Two-step distillation explained', 'Our two-step process for blending', 'Two step payment plan'])
    assert.equal(isSecurityMail({ from: 'x@example.com', subject }), false, subject);
  for (const subject of ['New two-step authentication method added', 'Your two-step authentication code', 'Turn on 2-Step Verification'])
    assert.equal(isSecurityMail({ from: 'x@example.com', subject }), true, subject);
  assert.ok(!SECURITY_SUBJECTS.includes('two-step'));
});

test('Gmail-Filter: Betreff auf mehrere Filter je < 1400 Zeichen, stabil (neue Phrasen nur im letzten), alle in Anführungszeichen', () => {
  assert.ok(SUBJECT_QUERIES.length >= 2);
  for (const q of SUBJECT_QUERIES) { assert.ok(q.length < FILTER_QUERY_MAX, `Länge ${q.length}`); assert.match(q, /^subject:\("[^+]*"\)$/); }
  assert.match(SUBJECT_QUERIES[0], /^subject:\("password reset" OR .*"alerte de sécurité"\)$/, 'erster Filter = bisherige Liste bis zum alten Ende');
  assert.match(SUBJECT_QUERY, / OR "2FA" OR /);
});

test('two-step und zweistufig mit Anmelde-Bezug wieder vollständig (reviewer S137)', () => {
  for (const subject of ['Two-step verification turned off for your account', 'Complete your two-step verification', 'Two-Step Login enabled',
    'Ihre zweistufige Authentifizierung wurde aktiviert', 'Veuillez vérifier votre identité'])
    assert.equal(isSecurityMail({ from: 'x@example.com', subject }), true, subject);
});

const umleitung = async () => { throw Object.assign(new TypeError('fetch failed'), { cause: new Error('unexpected redirect') }); };

test('Redirect: tokeninfo (grantedScopesOf) folgt keiner Weiterleitung, Fehler lesbar', async () => {
  const opts = [];
  await assert.rejects(grantedScopesOf({ access_token: 'ya.test' }, async (u, o) => { opts.push(o); return umleitung(); }), /tokeninfo leitet weiter/);
  assert.equal(opts[0].redirect, 'error');
});

test('Redirect: OAuth-Token-Datei (getAccessTokenFromFile) folgt keiner Weiterleitung, Fehler lesbar', async () => {
  const datei = path.join(tmpDir('redir-file-'), 'token-read-test.json');
  writeFileSync(datei, JSON.stringify({ refresh_token: 'r', client_id: 'c', client_secret: 's' }));
  const opts = [];
  await assert.rejects(getAccessTokenFromFile(datei, { fetchImpl: async (u, o) => { opts.push(o); return umleitung(); } }), /Token-Endpunkt leitet weiter/);
  assert.equal(opts[0].redirect, 'error');
});
