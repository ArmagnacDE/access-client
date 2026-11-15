// 1Password-Service-Account-Token aus einer Liste von Dateien wählen (access-client).
//
// Typischer Fall: ein neuer Service Account (~/.config/op/neu.token), der alte (alt.token) bleibt vorerst als
// Rückfall. Die Reihenfolge steht in der Konfiguration des Aufrufers (Feld tokenDateien), nicht im Code.
//
// Regeln:
// - Die erste VORHANDENE Datei gilt. Nur „gibt es nicht“ (ENOENT) führt zur nächsten.
// - Ist die erste vorhandene Datei unbrauchbar (kein reguläres File, Symlink, fremder Eigentümer, Rechte nicht genau
//   0600, nicht lesbar, keine ops_…-Form), ist das ein Stopp, kein stiller Rückfall: Ein kaputtes neues Token soll
//   auffallen und nicht vom alten verdeckt werden.
// - Prüfung und Lesen hängen an EINEM Dateideskriptor (open mit O_NOFOLLOW, dann fstat, dann lesen): Zwischen Prüfung
//   und Lesen kann die Datei nicht gegen eine andere getauscht werden.
// - Ausgegeben wird nur der Dateiname, nie der Inhalt. Ein ungültiger Konfigurationswert wird nur mit seiner Position
//   genannt, nicht mit seinem Text: Stünde dort versehentlich ein Token, käme es sonst in die Ausgabe.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export class OpTokenError extends Error {}

const FORM = /^ops_[A-Za-z0-9_\-.=]{20,}$/;

/** ~/… zum Home-Verzeichnis auflösen; nur absolute Pfade oder ~/… erlaubt. */
export function tokenPfad(p, home = os.homedir(), position = null) {
  const s = typeof p === 'string' ? p : '';
  const voll = s.startsWith('~/') ? path.join(home, s.slice(2)) : s;
  if (!path.isAbsolute(voll) || voll.includes('\0')) {
    throw new OpTokenError(`Token-Datei${position != null ? ` Nr. ${position}` : ''} in der Konfiguration: nur absolute Pfade oder ~/… (Wert nicht ausgegeben)`);
  }
  return path.normalize(voll);
}

// Dateiname einer Token-Datei: kurz, nur Zeichen eines Dateinamens, Endung .token. So kann auch ein versehentlich
// eingetragener Token-Wert („~/ops_…“) nicht als „Dateiname“ in eine Meldung gelangen.
const DATEINAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.token$/;

/** Konfigurierte Liste prüfen: 1–5 Einträge, ohne Doppel, Dateiname *.token. */
export function tokenListe(liste) {
  if (!Array.isArray(liste) || !liste.length || liste.length > 5) throw new OpTokenError('Konfiguration: tokenDateien fehlt oder hat mehr als 5 Einträge');
  const pfade = liste.map((p, i) => tokenPfad(p, os.homedir(), i + 1));
  pfade.forEach((p, i) => { if (!DATEINAME.test(path.basename(p))) throw new OpTokenError(`Token-Datei Nr. ${i + 1} in der Konfiguration: Dateiname muss auf .token enden und darf nur A–Z, 0–9, „._-“ enthalten (Wert nicht ausgegeben)`); });
  if (new Set(pfade).size !== pfade.length) throw new OpTokenError('Konfiguration: Token-Datei doppelt');
  return liste.map((p) => String(p));
}

/**
 * Erste vorhandene Token-Datei lesen.
 * @returns {{ datei: string, name: string, token: string }}  name = Dateiname (für die Ausgabe)
 */
export function waehleToken(liste, { dateisystem = fs, home = os.homedir(), uid = process.getuid?.() } = {}) {
  const gesucht = [];
  const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
  for (const [i, eintrag] of tokenListe(liste).entries()) {
    const datei = tokenPfad(eintrag, home, i + 1);
    const name = path.basename(datei);
    let fd;
    try { fd = dateisystem.openSync(datei, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); } catch (e) {
      if (e?.code === 'ENOENT') { gesucht.push(name); continue; }
      if (e?.code === 'ELOOP') throw new OpTokenError(`Token-Datei ${name} ist ein Symlink: Stopp, kein Rückfall`);
      throw new OpTokenError(`Token-Datei ${name} nicht lesbar (${e?.code ?? 'Fehler'}): Stopp, kein Rückfall`);
    }
    try {
      const st = dateisystem.fstatSync(fd);
      if (!st.isFile()) throw new OpTokenError(`Token-Datei ${name} ist keine reguläre Datei: Stopp, kein Rückfall`);
      if (uid != null && st.uid !== uid) throw new OpTokenError(`Token-Datei ${name} gehört nicht diesem Benutzer: Stopp, kein Rückfall`);
      if ((st.mode & 0o7777) !== 0o600) throw new OpTokenError(`Token-Datei ${name} hat Rechte ${(st.mode & 0o7777).toString(8)}, erwartet genau 600: Stopp, kein Rückfall`);
      let token;
      try { token = String(dateisystem.readFileSync(fd, 'utf8')).trim(); } catch (e) {
        throw new OpTokenError(`Token-Datei ${name} nicht lesbar (${e?.code ?? 'Fehler'}): Stopp, kein Rückfall`);
      }
      if (!FORM.test(token)) throw new OpTokenError(`Token-Datei ${name} hat keine gültige Form (ops_…): Stopp, kein Rückfall`);
      return { datei, name, token };
    } finally {
      try { dateisystem.closeSync(fd); } catch { /* schließen scheitert nur bei ungültigem fd */ }
    }
  }
  throw new OpTokenError(`Keine Token-Datei vorhanden (gesucht: ${gesucht.join(', ')})`);
}

/**
 * Token aus der Zugangs-Konfiguration (tokenDateien) wählen. Ein JSON-Fehler wird mit fester Meldung gemeldet:
 * die Meldung von JSON.parse zitiert sonst Zeichen um die Fehlerstelle, also womöglich einen Token-Wert.
 */
export function tokenAusKonfiguration(datei, optionen) {
  let roh;
  try { roh = fs.readFileSync(datei, 'utf8'); } catch (e) { throw new OpTokenError(`Zugangs-Konfiguration nicht lesbar (${e?.code ?? 'Fehler'})`); }
  let k;
  try { k = JSON.parse(roh); } catch { throw new OpTokenError('Zugangs-Konfiguration ist kein gültiges JSON'); } finally { roh = null; }
  return waehleToken(k?.tokenDateien, optionen);
}

/** JSON einer Konfigurationsdatei mit fester Fehlermeldung (kein Zitat aus dem Inhalt). */
export function konfigJson(datei) {
  try { return JSON.parse(fs.readFileSync(datei, 'utf8')); } catch (e) {
    throw new OpTokenError(e instanceof SyntaxError ? 'Zugangs-Konfiguration ist kein gültiges JSON' : `Zugangs-Konfiguration nicht lesbar (${e?.code ?? 'Fehler'})`);
  }
}
