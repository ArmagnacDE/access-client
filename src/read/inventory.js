// access-read access: Bestand an Zugängen einer Session, nur Metadaten (S110 (Diagnose Konten und Scopes)).
//
// Zeigt je Datei unter ~/.config/op/ (1Password-Service-Account-Tokens) und ~/.config/gsheets/ (Google-Credentials):
// Pfad, Rechte, Eigentum, Art. Mit --check zusätzlich, was jeder Zugang erreicht:
// - 1Password: Kontoangabe (op whoami) und Tresornamen (op vault list), beides über op-read; gelesen wird ein Token nur
//   über op-token (Rechte genau 600, eigener Benutzer, kein Symlink). Einträge liest der Befehl nie.
// - Google: Token-Dateien (refresh_token) werden erneuert, die Scopes meldet Google (tokeninfo); Dienstkonten melden
//   sich mit einem Lese-Scope an (prüft, ob der Schlüssel gilt). Ihre Delegierung steht nur in der Admin-Konsole.
//
// Nie Werte: kein Token, kein Refresh-Token, kein Client-Secret, kein Schlüssel, keine Tresor-IDs. Ausgegeben werden
// Dateinamen, Rechte, Typ, die Adresse eines Dienstkontos, Tresornamen und Scope-Namen. Fehler von op und Google gehen
// nur als feste Meldung hinaus (Kategorie bzw. bekannter OAuth-Fehlercode), nie als freier Text: op-stderr kann
// Tresor-IDs nennen, Google-Fehlerantworten Zugangsdaten zurückspiegeln (Codex-Befunde zu S110). Zusätzlich läuft jeder
// String der Ausgabe durch redact (cli.js), auch Pfade.

import { closeSync, constants as FS, fstatSync, lstatSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getAccessTokenFromFile, getServiceAccountToken, grantedScopesOf } from '../google-auth.js';
import { opVaultList, opWhoami } from '../op-read.js';
import { OpTokenError, waehleToken } from '../op-token.js';

const AUTH = 'https://www.googleapis.com/auth/';
const MAX_JSON = 256 * 1024;

export const opDir = (env = process.env) => env.ACCESS_OP_DIR || join(homedir(), '.config', 'op');
export const googleDir = (env = process.env) => env.GOOGLE_CONFIG_DIR || join(homedir(), '.config', 'gsheets');

const rechteVon = (st) => (st.mode & 0o7777).toString(8).padStart(3, '0');
const artVon = (st) => (st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'ordner' : st.isFile() ? 'datei' : 'sonstiges');

/** Einträge eines Ordners mit lstat (Symlinks werden nicht verfolgt), sortiert. */
function eintraege(ordner, uid) {
  let namen;
  try { namen = readdirSync(ordner); } catch (e) {
    return { fehler: e?.code === 'ENOENT' ? 'Ordner fehlt' : `Ordner nicht lesbar (${e?.code ?? 'Fehler'})`, liste: [] };
  }
  const liste = namen.sort().map((n) => {
    const datei = join(ordner, n);
    try {
      const st = lstatSync(datei);
      return { datei, st, basis: { datei, art: artVon(st), rechte: rechteVon(st), eigentum: uid == null || st.uid === uid ? 'eigen' : 'fremd' } };
    } catch (e) { return { datei, st: null, basis: { datei, art: 'unlesbar', fehler: e?.code ?? 'Fehler' } }; }
  });
  return { fehler: null, liste };
}

/** Kurzname eines Scopes (ohne https://www.googleapis.com/auth/). */
const kurz = (s) => (s.startsWith(AUTH) ? s.slice(AUTH.length) : s);

/** JSON einer Credential-Datei lesen, ohne Symlinks zu folgen, nicht blockierend, höchstens MAX_JSON Byte; nie Inhalt in
 *  eine Meldung. @returns {{ j: any, grund: string|null }} */
function leseJson(datei) {
  let fd;
  try {
    try { fd = openSync(datei, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK); } catch (e) {
      return { j: null, grund: e?.code === 'ELOOP' ? 'Symlink' : `nicht lesbar (${e?.code ?? 'Fehler'})` };
    }
    const st = fstatSync(fd);
    if (!st.isFile()) return { j: null, grund: 'keine reguläre Datei' };
    if (st.size > MAX_JSON) return { j: null, grund: `größer als ${MAX_JSON / 1024} KiB` };
    try { return { j: JSON.parse(readFileSync(fd, 'utf8')), grund: null }; } catch { return { j: null, grund: 'kein gültiges JSON' }; }
  } finally { if (fd != null) try { closeSync(fd); } catch { /* zu */ } }
}

// Bekannte OAuth-Fehlercodes (RFC 6749 und Google); nur diese gehen aus einer Google-Fehlerantwort in die Ausgabe.
const OAUTH_CODES = /\b(invalid_grant|invalid_client|unauthorized_client|invalid_scope|invalid_request|unsupported_grant_type|access_denied|deleted_client|disabled_client|org_internal|admin_policy_enforced|invalid_token)\b/;

/** Google-Fehler als feste Meldung: Art des Schritts und höchstens ein bekannter Fehlercode, nie der freie Text. */
export function googleFehler(e) {
  const m = String(e?.message ?? '');
  const code = OAUTH_CODES.exec(m)?.[1];
  if (/nicht erreichbar/.test(m)) return 'Google: Endpunkt nicht erreichbar';
  if (/tokeninfo|keine Scopes/.test(m)) return 'Google: Scopes nicht abfragbar';
  if (/nicht lesbar|refresh_token fehlt|kein gültiges JSON|private_key/.test(m) && !code) return 'Datei für die Anmeldung unbrauchbar';
  return `Google: Anmeldung fehlgeschlagen${code ? ` (${code})` : ''}`;
}

// Feste Meldungen von op-read, die keinen fremden Text enthalten (Prozessfehler und Antwortprüfung).
const OP_FEST = /(Zeitüberschreitung nach \d+ s|op-CLI nicht gefunden \(PATH\)|Ausgabe größer als \d+ Byte|Ausgabe zu groß|Fehlerausgabe zu groß|Antwort ist keine (Tresorliste|Kontoangabe)|Token fehlt oder hat keine gültige Form)/;

/** op-Fehler als feste Meldung: eine feste Meldung von op-read oder eine Kategorie aus Stichworten, nie stderr-Text. */
export function opFehler(e) {
  const m = String(e?.message ?? '');
  const fest = OP_FEST.exec(m)?.[1];
  if (fest) return `1Password: ${fest}`;
  const roh = `${m}\n${String(e?.opStderr ?? '')}`;
  let art = 'Text nicht ausgegeben';
  if (/rate limit|too many requests/i.test(roh)) art = 'Ratenlimit';
  else if (/invalid|revoked|unauthori[sz]ed|authenticat|expired/i.test(roh)) art = 'Token ungültig oder widerrufen';
  else if (/network|connection|dial tcp|no such host|tls|i\/o timeout|EOF/i.test(roh)) art = 'Netz';
  return `1Password: op meldet einen Fehler (${art})`;
}

/** OAuth-Token-Datei ohne eigene client_id/client_secret: google-auth liest dann oauth-client.json; das vorher sicher
 *  prüfen (keine FIFO, kein Symlink, Größe), sonst hinge ein readFileSync dort den ganzen Lauf auf. */
// google-auth nimmt die Felder der Token-Datei nur, wenn sie nicht leer sind (`||`), sonst oauth-client.json; flach oder
// unter installed/web.
function clientDateiOk(j, ordner) {
  if (j?.client_id && j?.client_secret) return true;
  const { j: oc } = leseJson(join(ordner, 'oauth-client.json'));
  const w = oc && typeof oc === 'object' ? (oc.installed || oc.web || oc) : null;
  return Boolean(w?.client_id && w?.client_secret);
}

/** Typ einer Google-Credential-Datei aus ihrem Aufbau; nur Typ und (bei Dienstkonten) die Adresse. */
export function googleTyp(j) {
  if (!j || typeof j !== 'object' || Array.isArray(j)) return { typ: 'unlesbar' };
  if (j.type === 'service_account') {
    const email = typeof j.client_email === 'string' && /^[a-z0-9._-]+@[a-z0-9.-]+$/i.test(j.client_email) ? j.client_email : null;
    return { typ: 'dienstkonto', email };
  }
  const w = j.installed || j.web || j;
  if (j.installed || j.web || (typeof w.client_id === 'string' && typeof w.client_secret === 'string' && !('refresh_token' in j))) return { typ: 'oauth-client' };
  if (typeof j.refresh_token === 'string') return { typ: 'oauth-token' };
  return { typ: 'unbekannt' };
}

/**
 * 1Password-Token-Dateien.
 * @param {{ check: boolean, env: object, exec?: Function, redact: (s: string) => string, uid?: number }} o
 */
export async function onePasswordInventory({ check, env, exec, redact, uid = process.getuid?.() }) {
  const ordner = opDir(env);
  const { fehler, liste } = eintraege(ordner, uid);
  const dateien = [];
  for (const { datei, st, basis } of liste) {
    const d = { ...basis };
    dateien.push(d);
    if (!st) { d.brauchbar = false; continue; }
    if (!datei.endsWith('.token')) { d.brauchbar = false; d.grund = 'keine Token-Datei (*.token)'; continue; }
    let token;
    try { ({ token } = waehleToken([datei], { uid })); } catch (e) {
      d.brauchbar = false;
      d.grund = e instanceof OpTokenError ? redact(e.message).slice(0, 200) : 'nicht prüfbar';
      continue;
    }
    d.brauchbar = true;
    if (!check) continue;
    const o = exec ? { token, exec } : { token };
    try {
      d.konto = await opWhoami(o);
      d.tresore = await opVaultList(o);
    } catch (e) { d.fehler = redact(opFehler(e)); }
  }
  return { ordner, ...(fehler ? { fehler } : {}), dateien };
}

/**
 * Google-Credentials.
 * @param {{ check: boolean, env: object, fetchImpl: typeof fetch, redact: (s: string) => string, uid?: number }} o
 */
export async function googleInventory({ check, env, fetchImpl, redact, uid = process.getuid?.() }) {
  const ordner = googleDir(env);
  const { fehler, liste } = eintraege(ordner, uid);
  const dateien = [];
  for (const { datei, st, basis } of liste) {
    const d = { ...basis };
    dateien.push(d);
    if (!st || !st.isFile()) continue;
    if (!datei.endsWith('.json')) { d.typ = 'keine JSON-Datei'; continue; }
    const { j, grund } = leseJson(datei);
    Object.assign(d, googleTyp(j));
    if (grund) d.grund = grund;
    if (!check) continue;
    try {
      if (d.typ === 'oauth-token') {
        if (!clientDateiOk(j, ordner)) { d.fehler = 'ohne client_id/client_secret und ohne brauchbare oauth-client.json daneben; nicht geprüft'; continue; }
        const accessToken = await getAccessTokenFromFile(datei, { fetchImpl });
        d.scopes = (await grantedScopesOf({ access_token: accessToken }, fetchImpl)).split(/\s+/).filter(Boolean).map(kurz).sort();
      } else if (d.typ === 'dienstkonto') {
        await getServiceAccountToken({ datei, scopes: [`${AUTH}spreadsheets.readonly`], fetchImpl });
        d.anmeldung = 'ok';
        d.scopes = 'je Anfrage; Delegierung nur in der Admin-Konsole sichtbar';
      }
    } catch (e) { d.fehler = redact(googleFehler(e)); }
  }
  return { ordner, ...(fehler ? { fehler } : {}), dateien };
}
