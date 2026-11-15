// Temp-Ordner für Tests: der einzige erlaubte Weg (hält /tmp klein, räumt auch bei Fehlern auf).
//
// Hintergrund: /tmp ist auf der VM ein tmpfs mit gut einer Million Inodes. Die Suite legte je Lauf
// tausende Ordner an und räumte sie nicht weg; am 19.10.2026 lief /tmp zweimal voll, danach scheiterte
// jedes mkdtemp in allen Sessions mit ENOSPC.
//
// Regeln:
// - tmpDir(prefix)      Ordner bleibt bis zum Ende des Testprozesses (node --test startet je Datei
//                       einen eigenen Prozess) und wird dann entfernt. Für Helfer ohne Test-Kontext und
//                       für Ordner auf Modulebene.
// - tmpDir(prefix, t)   zusätzlich gleich nach dem Test t entfernt (t.after), hält die Spitze klein.
// - withTmp(prefix, fn) Ordner nur für die Dauer von fn (sync oder async), Abbau im finally.
// Kindprozesse, die einen Pfad bekommen, sind beim Aufräumen schon beendet (Tests warten auf sie).
// Der Wächter test/tmp-leak.test.mjs prüft, dass keine Testdatei mkdtemp an diesem Helfer vorbei nutzt.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const offen = new Set();
let exitHook = false;

function entfernen(dir) {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* bleibt liegen, Wächter meldet es */ }
  offen.delete(dir);
}

/** Entfernt alle noch offenen Ordner dieses Prozesses (läuft automatisch beim Prozessende). */
export function cleanupTmp() {
  for (const dir of [...offen]) entfernen(dir);
}

function merken(dir) {
  offen.add(dir);
  if (!exitHook) {
    exitHook = true;
    process.on('exit', cleanupTmp);
  }
}

function anlegen(prefix) {
  if (typeof prefix !== 'string' || !prefix || /[/\\]/.test(prefix)) {
    throw new Error(`tmpDir: sprechendes Präfix ohne Pfadtrenner nötig, bekam ${JSON.stringify(prefix)}`);
  }
  return mkdtempSync(join(tmpdir(), prefix));
}

/**
 * Legt einen Temp-Ordner unter os.tmpdir() an und sorgt für seinen Abbau.
 * @param {string} prefix sprechend, z. B. 'ship-customs-'
 * @param {{ after?: Function }} [t] Test-Kontext von node:test: dann Abbau direkt nach dem Test
 * @returns {string} absoluter Pfad
 */
export function tmpDir(prefix, t) {
  const dir = anlegen(prefix);
  merken(dir);
  if (t && typeof t.after === 'function') t.after(() => entfernen(dir));
  return dir;
}

/**
 * Führt fn mit einem frischen Temp-Ordner aus und entfernt ihn danach, auch bei Fehlern.
 * Gibt das Ergebnis von fn zurück (bei async fn ein Promise).
 */
export function withTmp(prefix, fn) {
  const dir = anlegen(prefix);
  let result;
  try {
    result = fn(dir);
  } catch (e) {
    entfernen(dir);
    throw e;
  }
  if (result && typeof result.then === 'function') {
    merken(dir); // falls der Prozess endet, bevor das Promise fertig ist
    return Promise.resolve(result).finally(() => entfernen(dir));
  }
  entfernen(dir);
  return result;
}
