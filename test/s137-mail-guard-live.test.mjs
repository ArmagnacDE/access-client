// S137 (Mail-Wächter-Job live, 24.11.2026): Folgearbeit aus S123. „two-step“ allein traf „Two-step distillation“;
// Weiterleitungen des Token-Endpunkts auch auf den übrigen Token-Wegen lesbar abgebrochen. Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { SECURITY_SUBJECTS, SUBJECT_QUERY, isSecurityMail } from '../src/security-mail.js';
import { getAccessTokenFromFile, grantedScopesOf } from '../src/google-auth.js';
import { tmpDir } from './helpers/tmpdir.mjs';

test('two-step: nur mit Anmelde-Bezug (authentication; 2-Step Verification steht schon drin), nicht Destillation oder Zahlungsplan', () => {
  for (const subject of ['Two-step distillation explained', 'Our two-step process for blending', 'Two step payment plan'])
    assert.equal(isSecurityMail({ from: 'x@example.com', subject }), false, subject);
  for (const subject of ['New two-step authentication method added', 'Your two-step authentication code', 'Turn on 2-Step Verification'])
    assert.equal(isSecurityMail({ from: 'x@example.com', subject }), true, subject);
  assert.ok(!SECURITY_SUBJECTS.includes('two-step'));
});

test('Gmail-Filter: Einzelwörter mit + (dokumentierter exakter Worttreffer), Phrasen in Anführungszeichen; unter der Längengrenze', () => {
  assert.match(SUBJECT_QUERY, / OR \+2FA OR /);
  assert.match(SUBJECT_QUERY, / OR \+Sicherheitswarnung OR /);
  assert.match(SUBJECT_QUERY, / OR "two-step authentication" OR /);
  assert.match(SUBJECT_QUERY, / OR "Multi-Faktor" OR /, 'mit Bindestrich bleibt die Phrase in Anführungszeichen');
  assert.ok(SUBJECT_QUERY.length < 1400, `Länge ${SUBJECT_QUERY.length}`);
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
