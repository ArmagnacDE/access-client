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
// Dateinamen, Rechte, Typ, die Adresse eines Dienstkontos, Tresornamen und Scope-Namen. Fehlertexte laufen durch
// redact (cli.js) bzw. die Schwärzung von op-read.

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

/** JSON einer Credential-Datei lesen, ohne Symlinks zu folgen; nie Inhalt in eine Meldung. */
function leseJson(datei) {
  let fd;
  try {
    fd = openSync(datei, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_JSON) return null;
    return JSON.parse(readFileSync(fd, 'utf8'));
  } catch { return null; } finally { if (fd != null) try { closeSync(fd); } catch { /* zu */ } }
}

/** Typ einer Google-Credential-Datei aus ihrem Aufbau; nur Typ und (bei Dienstkonten) die Adresse. */
export function googleTyp(j) {
  if (!j || typeof j !== 'object' || Array.isArray(j)) return { typ: 'unlesbar' };
  if (j.type === 'service_account') {
    const email = typeof j.client_email === 'string' && /^[a-z0-9._-]+@[a-z0-9.-]+$/i.test(j.client_email) ? j.client_email : null;
    return { typ: 'dienstkonto', email };
  }
  if (j.installed || j.web) return { typ: 'oauth-client' };
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
    } catch (e) { d.fehler = redact(String(e?.message ?? e)).slice(0, 300); }
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
    Object.assign(d, googleTyp(leseJson(datei)));
    if (!check) continue;
    try {
      if (d.typ === 'oauth-token') {
        const accessToken = await getAccessTokenFromFile(datei, { fetchImpl });
        d.scopes = (await grantedScopesOf({ access_token: accessToken }, fetchImpl)).split(/\s+/).filter(Boolean).map(kurz).sort();
      } else if (d.typ === 'dienstkonto') {
        await getServiceAccountToken({ datei, scopes: [`${AUTH}spreadsheets.readonly`], fetchImpl });
        d.anmeldung = 'ok';
        d.scopes = 'je Anfrage; Delegierung nur in der Admin-Konsole sichtbar';
      }
    } catch (e) { d.fehler = redact(String(e?.message ?? e)).slice(0, 300); }
  }
  return { ordner, ...(fehler ? { fehler } : {}), dateien };
}
