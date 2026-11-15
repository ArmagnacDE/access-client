// Konten des Lese-Befehls access-read und ihre Zugänge.
//
// Grundsatz: Der Lese-Befehl bekommt nur Tokens, die schon bei Google NUR lesen dürfen.
// - Zugangsart „token“: eigene OAuth-Token-Datei je Postfach unter ~/.config/gsheets/ (erzeugt mit einer
//   OAuth-Anmeldung nur mit Lese-Scopes). Gemessen wird, was Google beim Erneuern meldet; ein Token mit irgendeinem
//   Scope außerhalb READ_ONLY_SCOPES (z. B. token.json des Inhabers mit drive/gmail.modify) wird abgelehnt.
// - Zugangsart „delegated“: domänenweit delegiertes Dienstkonto, angefragt wird je Aufruf genau EIN Lese-Scope;
//   auch hier wird gemessen, was Google für das Token meldet (Token-Antwort, sonst tokeninfo).
// Vor jedem Lesen prüft der Befehl, dass der Token wirklich zum Konto gehört (Gmail-Profil bzw. Drive „about“).
//
// Konfiguration: ~/.config/access-client/read.json (ACCESS_READ_CONFIG ersetzt den Pfad), Pflicht. Sie gehört dem
// Betreiber, nicht dem Paket, und enthält nur Adressen, Dateinamen und das Sperr-Label, keine Geheimnisse.

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { configDir, getAccessTokenFromFile, getDelegatedToken } from '../google-auth.js';

const AUTH = 'https://www.googleapis.com/auth/';
export const READ_SCOPE = Object.freeze({
  gmail: `${AUTH}gmail.readonly`,
  drive: `${AUTH}drive.readonly`,
  sheets: `${AUTH}spreadsheets.readonly`,
  docs: `${AUTH}documents.readonly`,
});
/** Alles, was ein Token des Lese-Befehls haben darf. openid kommt bei userinfo.email von Google ungefragt mit. */
export const READ_ONLY_SCOPES = Object.freeze([
  READ_SCOPE.gmail, `${AUTH}gmail.metadata`, READ_SCOPE.drive, READ_SCOPE.sheets, READ_SCOPE.docs,
  `${AUTH}userinfo.email`, 'openid',
]);


export class AccessReadError extends Error {
  constructor(message, { usage = false } = {}) { super(message); this.name = 'AccessReadError'; this.usage = usage; }
}

const NAME = /^[a-z][a-z0-9-]{0,30}$/;
const EMAIL = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;
// Nur ein Dateiname unter ~/.config/gsheets, kein Pfad. Generalschlüssel sind gesperrt, auch wenn sie den
// Scope-Test bestehen würden (token.json hat volle Rechte, oauth-client.json ist kein Token).
const FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const GESPERRT = new Set(['token.json', 'oauth-client.json']);

export const configPath = (env = process.env) => env.ACCESS_READ_CONFIG || join(homedir(), '.config', 'access-client', 'read.json');

/** Konfiguration prüfen; wirft mit Klartext, nennt nie Dateiinhalte. */
export function validateConfig(cfg) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw new AccessReadError('Konfiguration: kein Objekt');
  const unbekannt = Object.keys(cfg).filter((k) => !['accounts', 'filesAccount', 'gmailBlockedLabel', 'downloadDirs', '_doc'].includes(k));
  if (unbekannt.length) throw new AccessReadError(`Konfiguration: unbekannte Felder ${unbekannt.join(', ')}`);
  const acc = cfg.accounts;
  if (!acc || typeof acc !== 'object' || Array.isArray(acc) || !Object.keys(acc).length) throw new AccessReadError('Konfiguration: accounts fehlt');
  const out = {};
  const mails = new Set();
  for (const [name, a] of Object.entries(acc)) {
    if (!NAME.test(name)) throw new AccessReadError(`Konfiguration: Kontoname „${name.slice(0, 32)}“ ungültig (a–z, 0–9, -)`);
    if (!a || typeof a !== 'object') throw new AccessReadError(`Konto ${name}: kein Objekt`);
    const extra = Object.keys(a).filter((k) => !['email', 'token', 'delegated'].includes(k));
    if (extra.length) throw new AccessReadError(`Konto ${name}: unbekannte Felder ${extra.join(', ')}`);
    const email = String(a.email ?? '').toLowerCase();
    if (!EMAIL.test(email)) throw new AccessReadError(`Konto ${name}: email fehlt oder ungültig`);
    if (mails.has(email)) throw new AccessReadError(`Konto ${name}: Adresse doppelt`);
    mails.add(email);
    const arten = ['token', 'delegated'].filter((k) => a[k] != null);
    if (arten.length !== 1) throw new AccessReadError(`Konto ${name}: genau eins von token oder delegated angeben`);
    const file = String(a[arten[0]]);
    if (!FILE.test(file) || GESPERRT.has(file)) throw new AccessReadError(`Konto ${name}: ${arten[0]} muss ein Dateiname *.json unter ~/.config/gsheets sein (nicht token.json, nicht oauth-client.json)`);
    out[name] = Object.freeze({ name, email, kind: arten[0], file });
  }
  const filesAccount = cfg.filesAccount ?? null;
  if (filesAccount != null && !out[filesAccount]) throw new AccessReadError(`Konfiguration: filesAccount „${String(filesAccount).slice(0, 32)}“ ist kein Konto`);
  // Pflicht: ohne Sperr-Label liest der Befehl keine Mail (Sicherheitsmails, siehe src/gmail.js configureGmailGuard).
  if (typeof cfg.gmailBlockedLabel !== 'string' || !/^[a-z0-9-]{3,40}$/.test(cfg.gmailBlockedLabel)) {
    throw new AccessReadError('Konfiguration: gmailBlockedLabel fehlt oder ist ungültig (Label der Sicherheitsmails, z. B. „no-read“)');
  }
  // Optional: Ordner, in die --out schreiben darf (absolut oder ~/…); ohne Liste ist --out aus.
  const downloadDirs = cfg.downloadDirs ?? [];
  if (!Array.isArray(downloadDirs) || downloadDirs.length > 10 || downloadDirs.some((d) => typeof d !== 'string' || !(d.startsWith('/') || d.startsWith('~/')) || d.includes('\0'))) {
    throw new AccessReadError('Konfiguration: downloadDirs muss eine Liste absoluter Pfade (oder ~/…) sein, höchstens 10');
  }
  const dirs = Object.freeze(downloadDirs.map((d) => (d.startsWith('~/') ? join(homedir(), d.slice(2)) : d)));
  return Object.freeze({ accounts: Object.freeze(out), filesAccount, gmailBlockedLabel: cfg.gmailBlockedLabel, downloadDirs: dirs });
}

/** Konfiguration laden. Fehlt die Datei oder ist sie kaputt: Fehler, kein Rückfall auf irgendeinen Standard. */
export function loadConfig({ env = process.env, readFile = readFileSync } = {}) {
  const p = configPath(env);
  let roh;
  try { roh = readFile(p, 'utf8'); } catch (e) {
    if (e?.code === 'ENOENT') throw new AccessReadError(`Konfiguration ${p} fehlt (Aufbau: README, Abschnitt „Konfiguration“)`);
    throw new AccessReadError(`Konfiguration ${p} nicht lesbar (${e?.code ?? 'Fehler'})`);
  }
  let cfg;
  try { cfg = JSON.parse(roh); } catch { throw new AccessReadError(`Konfiguration ${p} ist kein gültiges JSON`); }
  return { ...validateConfig(cfg), source: p };
}

/** Konto über Namen („mail“) oder Adresse finden. */
export function resolveAccount(config, wer) {
  const w = String(wer ?? '').trim().toLowerCase();
  if (!w) throw new AccessReadError('Konto fehlt', { usage: true });
  const a = config.accounts[w] ?? Object.values(config.accounts).find((x) => x.email === w);
  if (!a) throw new AccessReadError(`Konto „${w.slice(0, 64)}“ unbekannt; bekannt: ${Object.values(config.accounts).map((x) => `${x.name} (${x.email})`).join(', ')}`);
  return a;
}

/**
 * Access-Token für ein Konto und einen Dienst (gmail, drive, sheets, docs). Wirft, wenn der Token mehr als Lesen darf.
 * @param {{ fetchImpl?: typeof fetch, env?: object }} [o]
 */
export async function readToken(account, service, { fetchImpl = fetch, env = process.env } = {}) {
  const scope = READ_SCOPE[service];
  if (!scope) throw new Error(`readToken: Dienst ${service} unbekannt`);
  const dir = env.GOOGLE_CONFIG_DIR || configDir();
  const datei = join(dir, account.file);
  try {
    if (account.kind === 'delegated') return await getDelegatedToken({ datei, sub: account.email, scopes: [scope], allowedScopes: READ_ONLY_SCOPES, fetchImpl });
    return await getAccessTokenFromFile(datei, { allowedScopes: READ_ONLY_SCOPES, fetchImpl });
  } catch (e) {
    if (e.message.startsWith(`Token-Datei ${datei} nicht lesbar (ENOENT)`) || e.message.startsWith(`Dienstkonto-Datei ${datei} nicht lesbar (ENOENT)`)) {
      throw new AccessReadError(`Konto ${account.name} (${account.email}): Token-Datei ${account.file} fehlt unter ${dir}. Der Inhaber erzeugt sie (README, Abschnitt „Tokens erzeugen“).`);
    }
    if (/andere Rechte als erlaubt/.test(e.message)) {
      throw new AccessReadError(`Konto ${account.name}: Zugang ${account.file} darf mehr als lesen; der Lese-Befehl nimmt nur Lese-Tokens (${e.message.split('(')[1]?.split(')')[0] ?? ''})`);
    }
    throw e;
  }
}
