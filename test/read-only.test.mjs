// Der Lese-Befehl bleibt lesend: src/read/* und bin/access-read.mjs kennen keine schreibende Methode und importieren
// keine schreibende Funktion. Wer hier etwas Schreibendes braucht, gehört nicht in access-read (README „Grenzen“).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const DATEIEN = [...readdirSync(join(ROOT, 'src/read')).map((f) => `src/read/${f}`), 'bin/access-read.mjs'];
const SCHREIBEND = ['createDraft', 'createCheckedDraft', 'gmailPost', 'readPortalCodeMails'];

test('Scan sieht die Dateien des Lese-Befehls', () => {
  for (const f of ['src/read/cli.js', 'src/read/accounts.js', 'src/read/google-read.js', 'bin/access-read.mjs']) assert.ok(DATEIEN.includes(f), f);
});

test('keine schreibende HTTP-Methode, keine Schreib-Module, keine Entwurfs-Funktion im Lese-Befehl', () => {
  for (const f of DATEIEN) {
    const src = readFileSync(join(ROOT, f), 'utf8');
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.ok(!new RegExp(`['"\`]${m}['"\`]`).test(src), `${f}: Methode ${m}`);
    assert.ok(!/from '\.\.\/(drive|sheets)\.js'/.test(src), `${f}: importiert ein Modul mit Schreibpfaden`);
    const imp = [...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'([^']+)'/g)].flatMap((m) => m[1].split(',').map((x) => x.trim().split(/\s+as\s+/)[0]));
    for (const w of SCHREIBEND) assert.ok(!imp.includes(w), `${f}: importiert ${w}`);
    assert.ok(!/upload|batchUpdate|:batch|permissions/i.test(src.replace(/\/\/.*$/gm, '')), `${f}: Schreib- oder Freigabe-Endpunkt`);
  }
});

test('Lesepfade im Code fest: Drive nur about/files/export, Sheets nur Metadaten und values', () => {
  const src = readFileSync(join(ROOT, 'src/read/google-read.js'), 'utf8');
  assert.match(src, /const DRIVE_PATH = \/\^\(about\|files\|files\\\/\[A-Za-z0-9_-\]\+\|files\\\/\[A-Za-z0-9_-\]\+\\\/export\)\$\/;/);
  assert.match(src, /method: 'GET'/);
});
