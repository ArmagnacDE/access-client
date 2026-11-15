// Token-Datei aus einer Liste wählen (src/op-token.js). Echte Dateien in einem Wegwerf-Verzeichnis, erfundene Tokens.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { waehleToken, tokenListe, tokenPfad, tokenAusKonfiguration, konfigJson, OpTokenError } from '../src/op-token.js';
import { tmpDir } from './helpers/tmpdir.mjs';

const T1 = `ops_${'a'.repeat(40)}`;
const T2 = `ops_${'b'.repeat(40)}`;
function home() {
  const h = tmpDir('op-token-');
  fs.mkdirSync(path.join(h, '.config/op'), { recursive: true });
  return h;
}
const schreibe = (h, name, inhalt, mode = 0o600) => { const p = path.join(h, '.config/op', name); fs.writeFileSync(p, inhalt, { mode }); fs.chmodSync(p, mode); return p; };
const LISTE = ['~/.config/op/neu.token', '~/.config/op/alt.token'];

test('erste vorhandene Datei gilt; fehlt sie, die nächste', () => {
  const h = home();
  schreibe(h, 'alt.token', `${T2}\n`);
  assert.deepEqual(waehleToken(LISTE, { home: h }), { datei: path.join(h, '.config/op/alt.token'), name: 'alt.token', token: T2 });
  schreibe(h, 'neu.token', T1);
  const w = waehleToken(LISTE, { home: h });
  assert.equal(w.name, 'neu.token');
  assert.equal(w.token, T1);
});

test('vorhandene, aber unbrauchbare erste Datei ist ein Stopp, kein Rückfall', () => {
  const h = home();
  schreibe(h, 'alt.token', T2);
  const p = schreibe(h, 'neu.token', T1, 0o644);
  assert.throws(() => waehleToken(LISTE, { home: h }), /Rechte 644, erwartet genau 600.*kein Rückfall/);
  fs.chmodSync(p, 0o600);
  fs.writeFileSync(p, 'kaputt');
  assert.throws(() => waehleToken(LISTE, { home: h }), /keine gültige Form/);
  fs.unlinkSync(p);
  fs.symlinkSync(path.join(h, '.config/op/alt.token'), p);
  assert.throws(() => waehleToken(LISTE, { home: h }), /ist ein Symlink.*kein Rückfall/);
  fs.unlinkSync(p);
  fs.mkdirSync(p);
  assert.throws(() => waehleToken(LISTE, { home: h }), /keine reguläre Datei/);
  fs.rmdirSync(p);
  schreibe(h, 'neu.token', T1);
  assert.throws(() => waehleToken(LISTE, { home: h, uid: 99999 }), /gehört nicht diesem Benutzer/);
});

test('keine Datei vorhanden; Meldungen enthalten nie den Inhalt', () => {
  const h = home();
  assert.throws(() => waehleToken(LISTE, { home: h }), /Keine Token-Datei vorhanden \(gesucht: neu.token, alt.token\)/);
  schreibe(h, 'neu.token', `ops_${'x'.repeat(5)}`);
  try { waehleToken(LISTE, { home: h }); assert.fail(); } catch (e) { assert.ok(e instanceof OpTokenError); assert.ok(!e.message.includes('xxxxx')); }
});

test('Konfiguration: Liste und Pfade', () => {
  assert.throws(() => tokenListe([]), OpTokenError);
  assert.throws(() => tokenListe(['a', 'b', 'c', 'd', 'e', 'f'].map((x) => `/t/${x}.token`)), OpTokenError);
  assert.throws(() => tokenListe(['/t/a.token', '/t//a.token']), /doppelt/);
  assert.throws(() => tokenPfad('relativ/token'), /absolute/);
  assert.equal(tokenPfad('~/.config/op/x.token', '/home/u'), '/home/u/.config/op/x.token');
  assert.deepEqual(tokenListe(['~/.config/op/neu.token', '~/.config/op/alt.token']), ['~/.config/op/neu.token', '~/.config/op/alt.token']);
});

test('Rechte genau 0600: 0400, 0700, 0640, 0604 und Sonderbits sind ein Stopp', () => {
  for (const mode of [0o400, 0o700, 0o640, 0o604, 0o4600, 0o1600]) {
    const h = home();
    schreibe(h, 'alt.token', T2);
    schreibe(h, 'neu.token', T1, mode);
    assert.throws(() => waehleToken(LISTE, { home: h }), new RegExp(`Rechte ${mode.toString(8)}, erwartet genau 600`), `mode ${mode.toString(8)}`);
  }
});

test('ungültiger Konfigurationswert erscheint nicht in der Meldung', () => {
  const geheim = `ops_${'g'.repeat(40)}`;
  for (const liste of [[geheim], ['~/.config/op/neu.token', geheim], [`relativ/${geheim}`]]) {
    try { tokenListe(liste); assert.fail('kein Fehler'); } catch (e) {
      assert.ok(e instanceof OpTokenError);
      assert.ok(!e.message.includes('ggggg'), e.message);
      assert.match(e.message, /Nr\. \d.*Wert nicht ausgegeben/);
    }
  }
  try { tokenPfad(geheim); assert.fail(); } catch (e) { assert.ok(!e.message.includes('ggggg')); }
  assert.throws(() => tokenListe([42]), /Nr\. 1/);
});

test('Prüfung und Lesen an einem Dateideskriptor: Tausch nach dem Prüfen liest nicht die neue Datei', () => {
  const h = home();
  const p = schreibe(h, 'neu.token', T1);
  const fremd = schreibe(h, 'fremd.token', T2);
  const fsTausch = { ...fs, fstatSync(fd) { const st = fs.fstatSync(fd); fs.renameSync(fremd, p); return st; } };
  const w = waehleToken(LISTE, { home: h, dateisystem: fsTausch });
  assert.equal(w.token, T1);
});

test('FIFO blockiert nicht und ist ein Stopp', { skip: process.platform === 'win32' }, async () => {
  const h = home();
  const p = path.join(h, '.config/op/neu.token');
  const { execFileSync } = await import('node:child_process');
  execFileSync('mkfifo', ['-m', '600', p]);
  assert.throws(() => waehleToken(LISTE, { home: h }), /keine reguläre Datei/);
});

test('Dateiname muss *.token sein; ein Token-Wert als Dateiname erscheint nicht', () => {
  const geheim = `ops_${'h'.repeat(40)}`;
  for (const liste of [[`~/${geheim}`], [`/${geheim}`], ['~/.config/op/neu.token', '/t/x.txt']]) {
    try { tokenListe(liste); assert.fail('kein Fehler'); } catch (e) { assert.ok(e instanceof OpTokenError); assert.ok(!e.message.includes('hhhhh'), e.message); assert.match(e.message, /Dateiname muss auf \.token enden/); }
  }
});

test('Zugangs-Konfiguration: JSON-Fehler mit fester Meldung, ohne Zitat aus dem Inhalt', () => {
  const h = home();
  const k = path.join(h, 'k.json');
  fs.writeFileSync(k, `{"tokenDateien": ["ops_${'q'.repeat(40)}",]}`);
  for (const f of [() => tokenAusKonfiguration(k, { home: h }), () => konfigJson(k)]) {
    try { f(); assert.fail(); } catch (e) { assert.ok(e instanceof OpTokenError); assert.equal(e.message, 'Zugangs-Konfiguration ist kein gültiges JSON'); }
  }
  assert.throws(() => tokenAusKonfiguration(path.join(h, 'fehlt.json')), /nicht lesbar \(ENOENT\)/);
  fs.writeFileSync(k, JSON.stringify({ tokenDateien: ['~/.config/op/neu.token'] }));
  schreibe(h, 'neu.token', T1);
  assert.equal(tokenAusKonfiguration(k, { home: h }).name, 'neu.token');
});

test('nicht lesbare Datei (Rechte 000) ist ein Stopp, kein Rückfall', { skip: process.getuid?.() === 0 }, () => {
  const h = home();
  schreibe(h, 'alt.token', T2);
  schreibe(h, 'neu.token', T1, 0o000);
  assert.throws(() => waehleToken(LISTE, { home: h }), /nicht lesbar \(EACCES\).*kein Rückfall/);
});
