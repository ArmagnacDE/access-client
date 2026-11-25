// 1Password lesen über die op-CLI: eine geprüfte Stelle für `op read` und `op vault get` (access-client).
//
// Regeln:
// - Der Aufrufer gibt das Service-Account-Token (z. B. aus op-token.js). Es geht NUR in die Umgebung des
//   op-Kindprozesses, nie nach process.env, nie in argv.
// - Umgebung des Kindprozesses: genau PATH (fest), HOME und OP_SERVICE_ACCOUNT_TOKEN. Keine geerbten OP_*-Variablen (etwa
//   OP_SESSION_…, OP_CONNECT_…), die einen anderen Zugang unterschieben könnten.
// - argv enthält nur den Unterbefehl und den op://-Verweis bzw. Tresornamen; beide werden vorher geprüft (keine
//   Steuerzeichen, kein führendes „-“, keine ?-Parameter wie ?attribute=otp).
// - Fehlermeldungen: erste nicht leere Zeile von stderr, gekürzt, Token-Wert und ops_…-Formen geschwärzt. stdout
//   erscheint nie in einer Meldung. Das ganze stderr (gekürzt) hängt nicht aufzählbar als `opStderr` am Fehler, damit
//   ein console.error(e) es nicht ausgibt.
// - „Gibt es nicht“ (Tresor, Eintrag oder Feld, belegter Wortlaut von op) ist eine eigene Fehlerklasse
//   (OpItemMissingError mit `was`), jeder andere Fehler (Token, Netz, Limit, Zeitüberschreitung) ist OpReadError.
// - `op read` gibt Binärdateien verfälscht aus (ungültiges UTF-8 → U+FFFD). opRead ist für Text-Geheimnisse
//   (Passwörter, API-Schlüssel); Dokumente gehören nicht hierher.
// - `op item get` nur in zwei engen Formen: Kopf eines Eintrags (ID, Titel, Feldnamen; nie Werte; der Puffer mit der
//   ganzen Antwort wird genullt, Kopien in Strings bleiben bis zur Speicherbereinigung) und der aktuelle Einmal-Code
//   (--otp, nur über die Eintrags-ID).
// - Kein Name in argv darf wie ein Token aussehen (ops_…); PATH des Kindprozesses ist fest, nicht geerbt.
// - Ein Abruf je Aufruf, kein Wiederholen (Limit 1.000 Lesezugriffe je Stunde und Token).

import os from 'node:os';
import { execFile } from 'node:child_process';
import { istKeinTresor, schreibweisen } from './op-vault.js';

export class OpReadError extends Error {
  constructor(message) { super(message); this.name = 'OpReadError'; }
}

/** Tresor, Eintrag oder Feld gibt es nicht (bzw. der Service Account sieht ihn nicht). `was`: tresor | eintrag | feld. */
export class OpItemMissingError extends OpReadError {
  constructor(message, was) { super(message); this.name = 'OpItemMissingError'; this.was = was; }
}

/** Ein Titel passt auf mehrere Einträge (op: „More than one item matches …“). */
export class OpItemAmbiguousError extends OpReadError {
  constructor(message) { super(message); this.name = 'OpItemAmbiguousError'; }
}

const KEIN_EINTRAG = /isn't an item/i;
const MEHRDEUTIG = /more than one (item|vault) matches/i;
const KEIN_FELD = /does not have a field|doesn't have a field|isn't a field|could not find field/i;
// Ein Teil eines op://-Verweises: keine Steuerzeichen, kein „/“, kein „?“ (Abfrage-Parameter), höchstens 128 Zeichen.
const TEIL = /^[^/?\u0000-\u001f\u007f]{1,128}$/;
const TOKEN_FORM = /^ops_[A-Za-z0-9_\-.=]{20,}$/;
// Etwas, das wie ein Service-Account-Token aussieht, darf nie als Name in argv landen.
const TOKENARTIG = /ops_[A-Za-z0-9]/;
const STANDARD_PATH = '/usr/local/bin:/usr/bin:/bin';
// Eingeordnet werden nur Zeilen bis zu dieser Länge (op schreibt kurze Zeilen; lange Zeilen kosten nur Rechenzeit).
const MAX_ZEILE = 2000;

/** Ein Name für argv: kein Token, sonst feste Meldung ohne Wert. */
function keinToken(wert, token, was) {
  if (TOKENARTIG.test(wert) || (token && wert.includes(token))) throw new OpReadError(`${was} ungültig (Wert nicht ausgegeben)`);
}

/** Tresorname prüfen, mit fester Meldung (die Meldung von schreibweisen zitiert den Namen, etwa ein falsch
 *  eingesetztes Token). */
function pruefeTresor(vault, token) {
  try { schreibweisen(vault); } catch { throw new OpReadError('Tresorname ungültig (Wert nicht ausgegeben)'); }
  keinToken(vault, token, 'Tresorname');
}

/** op://<tresor>/<eintrag>[/<abschnitt>]/<feld> prüfen; liefert die Teile. */
export function pruefeVerweis(ref, token = null) {
  const s = typeof ref === 'string' ? ref : '';
  if (!s.startsWith('op://') || s.length > 400) throw new OpReadError('op-Verweis ungültig (erwartet op://<Tresor>/<Eintrag>/<Feld>)');
  const teile = s.slice(5).split('/');
  if (teile.length < 3 || teile.length > 4 || !teile.every((t) => TEIL.test(t) && t.trim() === t)) {
    throw new OpReadError('op-Verweis ungültig (erwartet op://<Tresor>/<Eintrag>/<Feld>, ohne ?-Parameter)');
  }
  keinToken(s, token, 'op-Verweis');
  return teile;
}

function pruefeToken(token) {
  if (typeof token !== 'string' || !TOKEN_FORM.test(token)) throw new OpReadError('1Password-Token fehlt oder hat keine gültige Form (ops_…; Wert nicht ausgegeben)');
}

/**
 * Umgebung des op-Kindprozesses: nur PATH, HOME und das Token. PATH ist fest (/usr/local/bin:/usr/bin:/bin), nicht
 * geerbt: unter `npm run` stünde sonst node_modules/.bin vorn, und ein dort liegendes `op` bekäme das Token. Ein anderer
 * PATH nur ausdrücklich über `path`.
 */
export function opUmgebung(token, { path = STANDARD_PATH, home = os.homedir() } = {}) {
  return { PATH: path, HOME: home, OP_SERVICE_ACCOUNT_TOKEN: token };
}

/** Text schwärzen: Token-Wert und jede ops_…-Form (breiter als die Formprüfung, auch „+“ und „/“). */
export function schwaerze(text, token) {
  let s = String(text ?? '');
  if (token) s = s.split(token).join('[token]');
  return s.replace(/ops_[A-Za-z0-9_\-.=+/]{8,}/g, '[token]');
}

// Kopf einer op-Fehlerzeile: „[ERROR] 2026/11/15 10:00:00 “; ohne erkannten Zeitstempel nur „[ERROR] “.
const KOPF = /^\[ERROR\]\s*(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s*)?/;

/**
 * Bekannte Eingaben wörtlich aus einer Zeile entfernen, in der Form, in der op sie zitiert ("name" bzw. 'name').
 * So verschiebt ein Name wie „isn't a vault in this account“ die Einordnung nicht, unabhängig von Zitatzeichen im Namen.
 * Längere Namen zuerst (ein Verweis enthält seine Teile).
 */
function ohneNamen(zeile, namen) {
  let z = zeile;
  for (const n of [...namen].filter(Boolean).sort((x, y) => y.length - x.length)) {
    z = z.split(`"${n}"`).join('""').split(`'${n}'`).join("''");
  }
  return z;
}

function einordnenZeile(z) {
  if (MEHRDEUTIG.test(z)) return 'mehrdeutig';
  if (istKeinTresor(z)) return 'tresor';
  if (KEIN_EINTRAG.test(z)) return 'eintrag';
  if (KEIN_FELD.test(z)) return 'feld';
  return null;
}

/**
 * stderr fachlich einordnen. Nur Zeilen mit [ERROR]-Kopf zählen (Hinweiszeilen nicht), bekannte Namen werden vorher
 * entfernt. Ergebnis: { art: tresor | eintrag | feld | mehrdeutig | null, zeile } — zeile ist die Zeile für die
 * Meldung: die eingeordnete, sonst die erste [ERROR]-Zeile, sonst die erste nicht leere. Widersprechen sich zwei
 * eingeordnete Zeilen, ist art null (Stopp statt Raten).
 * @param {string} stderr
 * @param {string[]} [namen]  Tresor, Eintrag, Verweis und Verweisteile, wie an op übergeben
 */
export function einordnen(stderr, namen = []) {
  const zeilen = String(stderr ?? '').split('\n').map((z) => z.trim()).filter(Boolean);
  const fehler = zeilen.filter((z) => KOPF.test(z) && z.startsWith('[ERROR]'));
  let art = null;
  let zeile = null;
  for (const z of fehler) {
    if (z.length > MAX_ZEILE) continue;
    const a = einordnenZeile(ohneNamen(z, namen));
    if (!a) continue;
    if (art && a !== art) return { art: null, zeile: fehler[0] };
    art = a;
    zeile ??= z;
  }
  return { art, zeile: zeile ?? fehler[0] ?? zeilen[0] ?? '' };
}

/**
 * op ausführen. Liefert stdout als Buffer; wirft OpItemMissingError, OpItemAmbiguousError bzw. OpReadError.
 * @param {string[]} args  geprüfte Argumente
 */
function opAusfuehren(args, { token, exec, timeoutMs, maxBytes, path, home, was, namen }) {
  return new Promise((resolve, reject) => {
    let fertig = false;
    const cb = (err, stdout, stderr) => {
      if (fertig) return;
      fertig = true;
      if (!err) return resolve(Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout ?? ''), 'utf8'));
      // Fehler: stdout kann Geheimnisse enthalten (z. B. abgebrochene Antwort von op item get) → sofort nullen.
      if (Buffer.isBuffer(stdout)) stdout.fill(0);
      const roh = schwaerze(Buffer.isBuffer(stderr) ? stderr.toString('utf8') : stderr, token);
      // Prozessfehler gehen der fachlichen Einordnung vor und sind immer ein Stopp: Zeitüberschreitung, kein op,
      // Ausgabelimit, Tod durch ein Signal, jeder nicht numerische Code. Eingeordnet wird nur bei numerischem Exit-Code.
      // Das Ausgabelimit zuerst: execFile beendet den Kindprozess dabei selbst, ein Fehler mit killed/Signal ist dann
      // keine Zeitüberschreitung (S51). Aufrufer erkennen es an „Ausgabe zu groß“ (nicht wiederholen).
      let prozess = null;
      // stdout und stderr haben je ein eigenes Limit; nur ein Überlauf auf stdout heißt „Ausgabe zu groß“ (der Wert ist zu
      // groß, heilt nicht von selbst). Zu viel stderr (z. B. Fehlerseite eines Proxys) ist „Fehlerausgabe zu groß“.
      if (err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
        prozess = /^stderr\b/.test(String(err.message ?? '')) ? `Fehlerausgabe zu groß (mehr als ${maxBytes} Byte)` : `Ausgabe zu groß (mehr als ${maxBytes} Byte)`;
      } else if (err.killed || err.code === 'ETIMEDOUT') prozess = `Zeitüberschreitung nach ${Math.round(timeoutMs / 1000)} s`;
      else if (err.code === 'ENOENT') prozess = 'op-CLI nicht gefunden (PATH)';
      else if (err.signal) prozess = `op beendet durch ${String(err.signal).slice(0, 20)}`;
      else if (typeof err.code !== 'number') prozess = `op nicht ausführbar (${String(err.code ?? 'unbekannt').slice(0, 40)})`;
      const { art, zeile } = prozess ? { art: null, zeile: '' } : einordnen(roh, namen);
      const grund = (prozess ?? (zeile.replace(KOPF, '') || `Exit ${err.code}`)).slice(0, 200);
      const text = `1Password: ${was} fehlgeschlagen: ${grund}`;
      let e;
      if (art === 'tresor' || art === 'eintrag' || art === 'feld') e = new OpItemMissingError(text, art);
      else if (art === 'mehrdeutig') e = new OpItemAmbiguousError(text);
      else e = new OpReadError(text);
      // Für tresorSuche (op-vault.js): Fehler dieses Moduls sind schon eingeordnet, dort zählt nur `was`, kein Text.
      Object.defineProperty(e, 'opEingeordnet', { value: true, enumerable: false });
      Object.defineProperty(e, 'opStderr', { value: roh.slice(0, 4000), enumerable: false });
      reject(e);
    };
    try {
      exec('op', args, { env: opUmgebung(token, { path, home }), encoding: 'buffer', timeout: timeoutMs, maxBuffer: maxBytes, windowsHide: true }, cb);
    } catch (e) {
      cb(Object.assign(new Error('spawn'), { code: e?.code ?? 'Fehler' }), null, '');
    }
  });
}

/**
 * Ein Geheimnis lesen: `op read --no-newline <ref>`.
 * @param {{ ref: string, token: string, exec?: typeof execFile, timeoutMs?: number, maxBytes?: number,
 *           path?: string, home?: string }} o  path: PATH des Kindprozesses (Standard /usr/local/bin:/usr/bin:/bin)
 * @returns {Promise<Buffer>}  Wert ohne Zeilenende; der Aufrufer überschreibt ihn nach Gebrauch (fill(0))
 */
export async function opRead({ ref, token, exec = execFile, timeoutMs = 30_000, maxBytes = 64 * 1024, path, home } = {}) {
  pruefeToken(token);
  const teile = pruefeVerweis(ref, token);
  const namen = [ref, teile.join('/'), `${teile[0]}/${teile[1]}`, ...teile];
  const wert = await opAusfuehren(['read', '--no-newline', ref], { token, exec, timeoutMs, maxBytes, path, home, was: 'Lesen', namen });
  if (!wert.length) throw new OpReadError('1Password: Lesen lieferte einen leeren Wert');
  return wert;
}

/**
 * Tresor abfragen: `op vault get <name> --format json`. Passt als `vaultGet` für tresorSuche (op-vault.js):
 * „isn't a vault“ steht dort im Fehler (message bzw. opStderr) und führt zur anderen Schreibweise.
 * @returns {Promise<{ id: string, name: string }>}
 */
export async function opVaultGet({ vault, token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  pruefeTresor(vault, token);
  const out = await opAusfuehren(['vault', 'get', vault, '--format', 'json'], { token, exec, timeoutMs, maxBytes: 64 * 1024, path, home, was: 'Tresorabfrage', namen: [vault] });
  let j;
  try { j = JSON.parse(out.toString('utf8')); } catch { throw new OpReadError('1Password: Tresorabfrage lieferte kein JSON'); }
  if (!j || typeof j.id !== 'string' || typeof j.name !== 'string') throw new OpReadError('1Password: Tresorabfrage ohne id/name');
  return { id: j.id, name: j.name };
}

const EINTRAG_RE = /^[^\u0000-\u001f\u007f-][^\u0000-\u001f\u007f]{0,127}$/;
function pruefeEintrag(item, token) {
  if (typeof item !== 'string' || !EINTRAG_RE.test(item) || item.trim() !== item) throw new OpReadError('Eintragsname ungültig (Wert nicht ausgegeben)');
  keinToken(item, token, 'Eintragsname');
}
// 1Password-Eintrags-ID: 26 Zeichen a–z/0–9 (Spielraum 20–32).
const ITEM_ID = /^[a-z0-9]{20,32}$/;

/**
 * Kopf eines Eintrags: `op item get <eintrag> --vault <tresor> --format json`, davon nur ID, Titel und Feldnamen.
 * Die Antwort enthält den ganzen Eintrag samt Werten: Sie wird nur hier geparst und der Puffer danach genullt; der
 * daraus gelesene String und das geparste Objekt (und Teilstücke in execFile) bleiben bis zur Speicherbereinigung im
 * Speicher. Nach außen gehen keine Werte. `op item get` findet auch über Domain oder ID; ob der Titel passt, prüft der
 * Aufrufer. Bei einem Eintrag in beiden Schreibweisen eines Tresors: diese Funktion als `holen` für einEintrag nehmen
 * und erst danach lesen (einEintrag fragt beide Schreibweisen ab, bevor es „doppelt“ meldet).
 * @returns {Promise<{ id: string, title: string, fieldLabels: string[] }>}
 */
export async function opItemHead({ vault, item, token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  pruefeTresor(vault, token);
  pruefeEintrag(item, token);
  let roh = await opAusfuehren(['item', 'get', item, '--vault', vault, '--format', 'json'], { token, exec, timeoutMs, maxBytes: 1024 * 1024, path, home, was: 'Eintragsabfrage', namen: [vault, item] });
  let kopf = null;
  try {
    const j = JSON.parse(roh.toString('utf8'));
    if (j && typeof j.id === 'string') {
      kopf = { id: j.id, title: String(j.title ?? ''), fieldLabels: (Array.isArray(j.fields) ? j.fields : []).map((f) => f?.label).filter((l) => typeof l === 'string' && l) };
    }
  } catch { /* feste Meldung unten: ein Parse-Fehler zitiert sonst Teile des Eintrags */ } finally { roh.fill(0); roh = null; }
  if (!kopf) throw new OpReadError('1Password: Eintragsabfrage lieferte keinen lesbaren Eintrag');
  return kopf;
}

/**
 * Aktueller Einmal-Code eines Eintrags: `op item get <id> --vault <tresor> --otp` → Buffer (6–10 Ziffern). Nur mit
 * Eintrags-ID (aus opItemHead), nie mit Titel: op findet über Titel auch per Domain einen anderen Eintrag, und hier
 * kommen nur Ziffern zurück, an denen niemand den Treffer prüfen kann.
 */
export async function opItemOtp({ vault, itemId, token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  pruefeTresor(vault, token);
  if (typeof itemId !== 'string' || !ITEM_ID.test(itemId)) throw new OpReadError('Einmal-Code nur mit Eintrags-ID (aus opItemHead; Wert nicht ausgegeben)');
  const out = await opAusfuehren(['item', 'get', itemId, '--vault', vault, '--otp'], { token, exec, timeoutMs, maxBytes: 16 * 1024, path, home, was: 'Einmal-Code', namen: [vault, itemId] });
  const code = out.toString('utf8').trim();
  out.fill(0);
  if (!/^[0-9]{6,10}$/.test(code)) throw new OpReadError('1Password: Einmal-Code hat keine erwartete Form (Wert nicht ausgegeben)');
  return Buffer.from(code, 'utf8');
}

/** vaultGet-Funktion für tresorSuche({ vaultGet }) mit festem Token. */
export const vaultGetMit = (token, optionen = {}) => (vault) => opVaultGet({ ...optionen, vault, token });

// Ein Name aus einer op-Antwort, der ausgegeben werden darf: Text ohne Steuerzeichen, höchstens 200 Zeichen. Enthält er
// die Form eines Service-Account-Tokens (ops_ + mindestens 20 Zeichen), geht er nicht hinaus (Codex-Befund S110
// (Diagnose Konten und Scopes)); kurze Formen wie „Shops_Archiv“ bleiben (reviewer-Befund).
const AUSGABE_NAME = /^[^\u0000-\u001f\u007f]{1,200}$/;
const TOKEN_WERT = /ops_[A-Za-z0-9_\-.=+/]{20,}/;
const ausgabeText = (x) => (typeof x === 'string' && AUSGABE_NAME.test(x) && !TOKEN_WERT.test(x) ? x : null);
export const NAME_VERDECKT = '[Name nicht ausgegeben]';

/**
 * Tresore, die das Token sieht: `op vault list --format json`, davon nur die Namen (sortiert). Für die Diagnose
 * (access-read access --check, S110 (Diagnose Konten und Scopes)); liest keine Einträge.
 * @returns {Promise<string[]>}
 */
export async function opVaultList({ token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  const out = await opAusfuehren(['vault', 'list', '--format', 'json'], { token, exec, timeoutMs, maxBytes: 256 * 1024, path, home, was: 'Tresorliste', namen: [] });
  let j = null;
  try { j = JSON.parse(out.toString('utf8')); } catch { /* feste Meldung unten */ }
  // Ein tokenartiger Name wird einzeln verdeckt, die übrigen bleiben; Unlesbares (kein Text, Steuerzeichen) ist ein Fehler.
  const namen = Array.isArray(j) ? j.map((v) => (typeof v?.name === 'string' && AUSGABE_NAME.test(v.name) ? (ausgabeText(v.name) ?? NAME_VERDECKT) : null)) : null;
  if (!namen || namen.some((n) => n == null)) throw new OpReadError('1Password: Antwort ist keine Tresorliste');
  return namen.sort((a, b) => a.localeCompare(b));
}

/**
 * Wer ist das Token: `op whoami --format json`, davon nur Typ (z. B. SERVICE_ACCOUNT), Adresse und Konto-URL.
 * @returns {Promise<{ typ: string, email: string|null, url: string|null }>}
 */
export async function opWhoami({ token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  const out = await opAusfuehren(['whoami', '--format', 'json'], { token, exec, timeoutMs, maxBytes: 64 * 1024, path, home, was: 'Kontoabfrage', namen: [] });
  let j = null;
  try { j = JSON.parse(out.toString('utf8')); } catch { /* feste Meldung unten */ }
  const typ = j && !Array.isArray(j) ? ausgabeText(j.user_type) : null;
  if (!typ) throw new OpReadError('1Password: Antwort ist keine Kontoangabe');
  return { typ, email: ausgabeText(j.email), url: ausgabeText(j.url) };
}

/**
 * Name des Kontos hinter dem Token: `op user get --me --format json`, davon nur Name, Typ und Status. `op whoami` nennt
 * den Namen eines Service Accounts nicht (S146 (access-read access: schneller und Register-Lücken)).
 * @returns {Promise<{ name: string|null, typ: string, status: string|null }>}
 */
export async function opSelf({ token, exec = execFile, timeoutMs = 30_000, path, home } = {}) {
  pruefeToken(token);
  const out = await opAusfuehren(['user', 'get', '--me', '--format', 'json'], { token, exec, timeoutMs, maxBytes: 64 * 1024, path, home, was: 'Kontoabfrage', namen: [] });
  let j = null;
  try { j = JSON.parse(out.toString('utf8')); } catch { /* feste Meldung unten */ }
  const typ = j && !Array.isArray(j) ? ausgabeText(j.type) : null;
  if (!typ) throw new OpReadError('1Password: Antwort ist keine Kontoangabe');
  const name = typeof j.name === 'string' && AUSGABE_NAME.test(j.name) ? (ausgabeText(j.name) ?? NAME_VERDECKT) : null;
  return { name, typ, status: ausgabeText(j.state) };
}
