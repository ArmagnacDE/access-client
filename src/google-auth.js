// Google-Anmeldung (access-client). Holt Access-Tokens aus den Credentials unter ~/.config/gsheets/ (Inhaber-Token,
// Token-Datei je Postfach, Dienstkonto, delegiertes Dienstkonto). Keine Fremd-Abhängigkeiten (Node ≥ 22, natives
// fetch). GOOGLE_CONFIG_DIR ersetzt ~/.config/gsheets (Tests und abweichende Installationen).
// Access-Tokens werden für die Lebensdauer des Prozesses im Speicher gehalten.
//
// Dienstkonto (unbeaufsichtigte Jobs): Ist GOOGLE_SERVICE_ACCOUNT_FILE gesetzt, meldet sich der Prozess NUR als Dienstkonto an
// (JWT-Bearer-Grant, RS256 mit node:crypto) — kein Rückfall auf den OAuth-Token des Inhabers,
// auch wenn der zufällig vorhanden ist. Das Dienstkonto sieht nur Dateien, die an seine Adresse
// freigegeben sind; Scope standardmäßig nur Sheets.
//
// GOOGLE_SERVICE_ACCOUNT_SCOPES: optional, Leerzeichen- oder Komma-Liste von Scope-URLs https://www.googleapis.com/auth/…
// (z. B. spreadsheets + drive). Ohne Variable (oder leer) bleibt es bei SA_SCOPES. Gmail-Scopes werden abgelehnt: Mails
// laufen über einen eigenen, ausdrücklich übergebenen Zugang (getDelegatedToken, getAccessTokenFromFile).
//
// Domänenweit delegiertes Dienstkonto: eigenes Konto mit eigener Schlüsseldatei, handelt für genau ein Postfach.
// getDelegatedToken() nimmt Datei, Postfach und Scopes ausdrücklich entgegen und teilt sich weder
// Cache noch Umgebungsvariable mit getAccessToken() — kein Job bekommt es aus Versehen.
//
// Schlüssel als Wert (ab v1.8.0, S40 „Google-Schlüssel ohne Datei“): Statt eines Pfads nehmen getDelegatedToken und
// getServiceAccountToken `key` (Objekt, JSON-Text oder Buffer, z. B. aus op-read opDocumentGet), getAccessToken liest
// GOOGLE_SERVICE_ACCOUNT_KEY (JSON-Text) statt GOOGLE_SERVICE_ACCOUNT_FILE. Genau eine Quelle: beides zugleich bricht
// ab. Caches hängen am Fingerabdruck (SHA-256 über Konto und privaten Schlüssel), nie am Schlüssel selbst; keine
// Meldung zitiert den Inhalt.

import { readFileSync } from 'node:fs';
import { createSign, createHash, createPrivateKey } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Ordner der Google-Credentials, je Aufruf gelesen (Tests setzen GOOGLE_CONFIG_DIR). */
export const configDir = () => process.env.GOOGLE_CONFIG_DIR || join(homedir(), '.config', 'gsheets');

function loadCreds() {
  // Cloud-Routines haben kein ~/.config/gsheets — dort kommen die Credentials
  // als Environment-Secrets. Lokal gewinnen weiterhin die Dateien.
  const env = process.env;
  if (env.GOOGLE_OAUTH_REFRESH_TOKEN && env.GOOGLE_OAUTH_CLIENT_ID && env.GOOGLE_OAUTH_CLIENT_SECRET) {
    return {
      clientId: env.GOOGLE_OAUTH_CLIENT_ID,
      clientSecret: env.GOOGLE_OAUTH_CLIENT_SECRET,
      refreshToken: env.GOOGLE_OAUTH_REFRESH_TOKEN,
    };
  }
  const token = JSON.parse(readFileSync(join(configDir(), 'token.json'), 'utf8'));
  let clientId = token.client_id;
  let clientSecret = token.client_secret;
  if (!clientId || !clientSecret) {
    const oc = JSON.parse(readFileSync(join(configDir(), 'oauth-client.json'), 'utf8'));
    const w = oc.installed || oc.web || oc;
    clientId = clientId || w.client_id;
    clientSecret = clientSecret || w.client_secret;
  }
  if (!token.refresh_token) {
    throw new Error('No refresh_token in ~/.config/gsheets/token.json');
  }
  return { clientId, clientSecret, refreshToken: token.refresh_token };
}

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const SA_SCOPES = 'https://www.googleapis.com/auth/spreadsheets';
// Präfix exakt (Großschreibung zählt); nur der Name darf Großbuchstaben haben, damit „GMAIL.x“ als Gmail auffällt.
const SCOPE_URL = /^https:\/\/www\.googleapis\.com\/auth\/[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Scopes fürs Dienstkonto aus GOOGLE_SERVICE_ACCOUNT_SCOPES (leer/ungesetzt → SA_SCOPES). Exportiert für den Test.
 *  Wirft bei allem, was keine Google-Scope-URL ist, und bei Gmail-Scopes. */
export function serviceAccountScopes(raw = process.env.GOOGLE_SERVICE_ACCOUNT_SCOPES) {
  if (raw == null || !String(raw).trim()) return SA_SCOPES;
  const liste = [...new Set(String(raw).split(/[\s,]+/).filter(Boolean))];
  // Nur Trenner („,“, „ , “): kein stiller Lauf mit leerem scope.
  if (!liste.length) throw new Error('GOOGLE_SERVICE_ACCOUNT_SCOPES enthält nur Trennzeichen, keine Scope-URL');
  for (const s of liste) {
    if (!SCOPE_URL.test(s)) {
      throw new Error(`GOOGLE_SERVICE_ACCOUNT_SCOPES: „${s}“ ist keine erlaubte Scope-URL (nur https://www.googleapis.com/auth/…)`);
    }
    if (/^gmail(\.|$)/i.test(s.slice('https://www.googleapis.com/auth/'.length))) {
      throw new Error(`GOOGLE_SERVICE_ACCOUNT_SCOPES: Gmail-Scope „${s}“ nicht erlaubt (Mails nur über einen ausdrücklich übergebenen Zugang)`);
    }
  }
  return liste.join(' ');
}

const b64url = (x) => Buffer.from(x).toString('base64url');

// Antworten des Token-Endpunkts: nie Parser- oder Rohtext in eine Meldung (er könnte ein Token-Fragment enthalten),
// und ein Access-Token muss wie eines aussehen (keine Steuerzeichen, die später in einem Header landen).
const ACCESS_TOKEN_RE = /^[\x21-\x7e]{1,4096}$/;
/** Grund eines Netzfehlers für die Meldung. Google-Endpunkte werden ohne Weiterleitung abgefragt (redirect: 'error',
 *  S123 „Mail-Weg Nacharbeiten“): ein Umleiten (Proxy, Captive Portal, falsche token_uri) erschien bisher nur als
 *  „TypeError“; jetzt steht da, was passiert ist. */
export function netzGrund(e) {
  if (/redirect/i.test(String(e?.cause?.message ?? e?.message ?? ''))) return 'leitet weiter (Redirect), abgebrochen; Netz oder Proxy prüfen';
  return `nicht erreichbar (${e?.cause?.code ?? e?.name ?? 'Fehler'})`;
}
async function tokenJson(res, was) {
  let json;
  try { json = await res.json(); } catch { throw new Error(`${was}: Antwort ist kein gültiges JSON (HTTP ${res.status})`); }
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error(`${was}: Antwort ist kein Objekt (HTTP ${res.status})`);
  if (res.ok && (typeof json.access_token !== 'string' || !ACCESS_TOKEN_RE.test(json.access_token))) throw new Error(`${was}: Antwort ohne gültiges access_token`);
  return json;
}
const fehlerText = (json) => [json?.error, json?.error_description].filter((x) => typeof x === 'string').join(' ').replace(/[^\x20-\x7e\u00c0-\u024f]/g, '').slice(0, 200);

/**
 * Scopes, die Google für ein Access-Token meldet: aus der Token-Antwort, sonst per tokeninfo (POST, das Token steht
 * nicht in der URL). Ohne Angabe: Fehler, nie „keine Scopes = alles gut“.
 */
export async function grantedScopesOf(json, fetchImpl = fetch) {
  if (typeof json?.scope === 'string' && json.scope.trim()) return json.scope.trim();
  let res;
  try {
    res = await fetchImpl('https://oauth2.googleapis.com/tokeninfo', { method: 'POST', body: new URLSearchParams({ access_token: json.access_token }), redirect: 'error', signal: AbortSignal.timeout(20_000) });
  } catch (e) { throw new Error(`tokeninfo ${netzGrund(e)}`); }
  let info = null;
  try { info = await res.json(); } catch { /* unten */ }
  if (!res.ok || typeof info?.scope !== 'string' || !info.scope.trim()) throw new Error('Google meldet keine Scopes für das Token; Rechte nicht prüfbar');
  return info.scope.trim();
}
/** Wirft, wenn granted (Leerzeichen-Liste) einen Scope außerhalb allowed enthält. */
export function assertScopesWithin(granted, allowed, was) {
  const extra = String(granted).split(/\s+/).filter((x) => x && !allowed.includes(x));
  if (extra.length) throw new Error(`${was} hat andere Rechte als erlaubt (${extra.join(', ')}); erlaubt nur: ${allowed.join(', ')}`);
}

/** Signierte JWT-Assertion fürs Dienstkonto (RFC 7523). Exportiert für den Test.
 *  `sub` = Postfach, in dessen Namen das Konto handelt (nur mit domänenweiter Delegierung). */
export function serviceAccountAssertion(sa, nowSek = Math.floor(Date.now() / 1000), { scope = SA_SCOPES, sub } = {}) {
  if (!sa?.client_email || !sa?.private_key) throw new Error('Dienstkonto-Datei ohne client_email/private_key');
  const kopf = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const inhalt = b64url(JSON.stringify({
    iss: sa.client_email, ...(sub ? { sub } : {}), scope, aud: TOKEN_URL,
    iat: nowSek, exp: nowSek + 3600,
  }));
  const signatur = createSign('RSA-SHA256').update(`${kopf}.${inhalt}`).sign(sa.private_key).toString('base64url');
  return `${kopf}.${inhalt}.${signatur}`;
}

/**
 * Dienstkonto-Schlüssel aus einem Wert: Objekt, JSON-Text oder Buffer (der Buffer wird nicht verändert; nullen tut der
 * Aufrufer). Liefert eine eigene, flache Kopie. Prüft nur die Form (type service_account, client_email, private_key)
 * und optional die Client-ID; Meldungen nennen nie den Inhalt.
 * @param {object|string|Buffer} wert
 * @param {{ clientId?: string, was?: string }} [o]  was: Bezeichnung in Meldungen
 * @returns {{ type: string, client_email: string, private_key: string, client_id?: string }}
 */
export function parseServiceAccountKey(wert, { clientId = null, was = 'Dienstkonto-Schlüssel' } = {}) {
  if (wert == null) throw new Error(`${was} fehlt`);
  let j;
  if (Buffer.isBuffer(wert) || typeof wert === 'string') {
    const text = Buffer.isBuffer(wert) ? wert.toString('utf8') : wert;
    if (!text.trim()) throw new Error(`${was} ist leer`);
    // Nie die Meldung von JSON.parse übernehmen: sie zitiert Teile des Textes.
    try { j = JSON.parse(text); } catch { throw new Error(`${was}: kein gültiges JSON (Inhalt nicht ausgegeben)`); }
  } else if (typeof wert === 'object') {
    j = wert;
  } else {
    throw new Error(`${was}: erwartet Objekt, JSON-Text oder Buffer`);
  }
  if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error(`${was}: kein Objekt`);
  if (j.type !== 'service_account') throw new Error(`${was}: kein Dienstkonto-Schlüssel (type ist nicht service_account)`);
  if (typeof j.client_email !== 'string' || !j.client_email) throw new Error(`${was} ohne client_email`);
  if (typeof j.private_key !== 'string' || !j.private_key) throw new Error(`${was} ohne private_key`);
  // Früh und mit fester Meldung statt erst beim Signieren mit der OpenSSL-Meldung (reviewer S40 #4), z. B. doppelt
  // maskierte Zeilenumbrüche nach einem Env-Transport. Ohne cause: die Ursache bleibt drinnen.
  try { createPrivateKey(j.private_key); } catch { throw new Error(`${was}: private_key nicht als Schlüssel lesbar (Inhalt nicht ausgegeben)`); }
  if (clientId != null && String(j.client_id) !== String(clientId)) {
    throw new Error(`${was} gehört zu einem anderen Dienstkonto (client_id passt nicht zu ${clientId})`);
  }
  return { ...j };
}

/** Fingerabdruck eines Schlüssels für Cache-Schlüssel: nie der Schlüssel selbst als Map-Schlüssel. */
const fingerabdruck = (sa) => createHash('sha256').update(JSON.stringify([sa.client_email, sa.private_key])).digest('hex');

/** Genau eine Quelle (datei oder key) → { sa, id }; id ist der Cache-Teil (Pfad bzw. Fingerabdruck).
 *  BEWUSST NICHT UMGESETZT (Codex S40 A2): Dateiquellen bleiben am Pfad gecacht wie vor v1.8.0. Wird die Datei im
 *  laufenden Prozess gegen einen anderen Schlüssel getauscht, gilt das alte Token bis zum Ablauf (≤ 1 h) weiter. Das
 *  ist alter Bestand; den Fingerabdruck auch für Dateien hieße, die Datei vor jedem Cache-Treffer zu lesen
 *  (Verhaltensänderung des Pfad-Wegs, den S40 unverändert lassen soll). */
function schluesselQuelle({ datei, key }, wer) {
  if (datei && key != null) throw new Error(`${wer}: entweder datei oder key, nicht beides`);
  if (key != null) {
    const sa = parseServiceAccountKey(key);
    return { sa, id: `key:${fingerabdruck(sa)}` };
  }
  if (!datei) return null;
  return { datei, id: `datei:${datei}` };
}

function ausDateiLesen(datei) {
  // Nie den Dateiinhalt in eine Fehlermeldung — er ist der private Schlüssel.
  try { return JSON.parse(readFileSync(datei, 'utf8')); } catch (e) {
    throw new Error(`Dienstkonto-Datei ${datei} nicht lesbar (${e.code ?? 'kein gültiges JSON'})`);
  }
}

/** Token per JWT-Bearer. quelle: { datei } (Datei lesen) oder { sa } (Schlüssel schon als Objekt). */
async function serviceAccountToken(quelle, opts, fetchImpl = fetch) {
  const sa = quelle.sa ?? ausDateiLesen(quelle.datei);
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: serviceAccountAssertion(sa, undefined, opts),
  });
  // Zeitlimit: --pruefe im Deploy darf an einem hängenden Token-Endpunkt nicht ewig warten.
  let res;
  try {
    // Fester Endpunkt: token_uri aus der Schlüsseldatei zählt nicht (eine veränderte Datei lenkte sonst die signierte
    // Assertion um; S112, wie OpenClaw gmail.js seit S5).
    res = await fetchImpl(TOKEN_URL, { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  } catch (e) { throw new Error(`Google-Dienstkonto-Anmeldung: Token-Endpunkt ${netzGrund(e)}`); }
  const json = await tokenJson(res, 'Google-Dienstkonto-Anmeldung');
  if (!res.ok) throw new Error(`Google-Dienstkonto-Anmeldung fehlgeschlagen: ${fehlerText(json) || res.status}`);
  return json;
}

let cached = null; // { accessToken, expiresAt, quelle }

/**
 * Welche Dienstkonto-Quelle getAccessToken() nimmt: 'key' (GOOGLE_SERVICE_ACCOUNT_KEY gesetzt, auch leer: dann bricht
 * getAccessToken ab), 'file' (GOOGLE_SERVICE_ACCOUNT_FILE nicht leer) oder null (Inhaber-Token). Beide → wirft. Für
 * Aufrufer, die die Zugangsart vorab prüfen oder melden (reviewer S40 #3), damit niemand die Regel nachbaut. Liest
 * nur, ob die Variablen gesetzt sind, nie den Inhalt.
 * @param {Record<string, string|undefined>} [env]
 * @returns {'key'|'file'|null}
 */
export function serviceAccountSource(env = process.env) {
  const mitWert = env.GOOGLE_SERVICE_ACCOUNT_KEY !== undefined;
  // Genau eine Quelle: welcher Schlüssel gewinnt, wäre sonst Zufall der Reihenfolge.
  if (env.GOOGLE_SERVICE_ACCOUNT_FILE && mitWert) throw new Error('GOOGLE_SERVICE_ACCOUNT_FILE und GOOGLE_SERVICE_ACCOUNT_KEY zugleich gesetzt: nur eine Quelle für das Dienstkonto');
  return mitWert ? 'key' : env.GOOGLE_SERVICE_ACCOUNT_FILE ? 'file' : null;
}

export async function getAccessToken() {
  // Zugangsart VOR dem Cache bestimmen: ein gecachtes Inhaber-Token darf nie für einen Aufruf
  // gelten, der das Dienstkonto verlangt.
  // Gesetzt heißt gesetzt, auch leer (Codex S40 A1): ein gescheiterter Abruf, der '' hinterlässt, darf nie still zum
  // Inhaber-Token führen. _FILE behält seine bisherige Bedeutung (leer = ungesetzt).
  const art = serviceAccountSource();
  const sa = art === 'key' ? schluesselQuelle({ key: parseServiceAccountKey(process.env.GOOGLE_SERVICE_ACCOUNT_KEY, { was: 'GOOGLE_SERVICE_ACCOUNT_KEY' }) }, 'getAccessToken')
    : art === 'file' ? schluesselQuelle({ datei: process.env.GOOGLE_SERVICE_ACCOUNT_FILE }, 'getAccessToken') : null;
  // Scopes gehören zur Zugangsart: ein Sheets-only-Token darf nie für einen Drive-Aufruf gelten und umgekehrt.
  const saScope = sa ? serviceAccountScopes() : null;
  const quelle = sa ? `sa:${sa.id}|${saScope}` : 'oauth';
  if (cached && cached.quelle === quelle && cached.expiresAt > Date.now() + 60_000) {
    return cached.accessToken;
  }
  if (sa) {
    const json = await serviceAccountToken(sa, { scope: saScope });
    cached = { accessToken: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000, quelle };
    return cached.accessToken;
  }
  const { clientId, clientSecret, refreshToken } = loadCreds();
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });
  let res;
  try {
    res = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  } catch (e) { throw new Error(`Google token refresh: Token-Endpunkt ${netzGrund(e)}`); }
  const json = await tokenJson(res, 'Google token refresh');
  if (!res.ok) {
    throw new Error(`Google token refresh failed: ${fehlerText(json) || res.status}`);
  }
  cached = {
    accessToken: json.access_token,
    expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000,
    quelle,
  };
  return cached.accessToken;
}

const delegiert = new Map();   // `${quelle}|${sub}|${scopes}` → { accessToken, expiresAt }

/** Token eines domänenweit delegierten Dienstkontos für genau ein Postfach.
 *  Schlüssel: `datei` (Pfad) oder `key` (Objekt, JSON-Text oder Buffer; ab v1.8.0), genau eins von beiden.
 *  allowedScopes (optional): Liste der Scopes, die das Token höchstens haben darf; gemessen wird, was Google meldet
 *  (Token-Antwort, sonst tokeninfo). Ohne Angabe keine Prüfung (wie bisher).
 *  @param {{ datei?: string, key?: object|string|Buffer, sub: string, scopes: string[], allowedScopes?: string[]|null, fetchImpl?: typeof fetch }} p */
export async function getDelegatedToken({ datei, key, sub, scopes, allowedScopes = null, fetchImpl = fetch }) {
  const q = schluesselQuelle({ datei, key }, 'getDelegatedToken');
  // Ohne key wörtlich die bisherige Meldung (Codex S40 A3).
  if (!q || !sub || !scopes?.length) throw new Error(`getDelegatedToken: ${key != null ? 'key' : 'datei'}, sub und scopes sind Pflicht`);
  const schluessel = `${q.id}|${sub}|${scopes.join(' ')}`;
  const c = delegiert.get(schluessel);
  if (c && c.expiresAt > Date.now() + 60_000) {
    if (allowedScopes) assertScopesWithin(c.scope ?? (c.scope = await grantedScopesOf({ access_token: c.accessToken }, fetchImpl)), allowedScopes, `Dienstkonto ${sub}`);
    return c.accessToken;
  }
  const json = await serviceAccountToken(q, { scope: scopes.join(' '), sub }, fetchImpl);
  const scope = allowedScopes ? await grantedScopesOf(json, fetchImpl) : (typeof json.scope === 'string' ? json.scope : null);
  if (allowedScopes) assertScopesWithin(scope, allowedScopes, `Dienstkonto ${sub}`);
  delegiert.set(schluessel, { accessToken: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000, scope });
  return json.access_token;
}

const eigeneScopes = new Map();   // `${quelle}|${scopes}` → { accessToken, expiresAt }

/** Token eines Dienstkontos mit ausdrücklich genannten Scopes, ohne Delegierung (z. B. Scope content).
 *  Unabhängig von GOOGLE_SERVICE_ACCOUNT_SCOPES und vom Cache in getAccessToken(): ein Job bekommt so nur den Scope,
 *  den er selbst anfordert, und andere Jobs im selben Prozess bekommen ihn nicht.
 *  Schlüssel: `datei` (Pfad) oder `key` (Objekt, JSON-Text oder Buffer; ab v1.8.0), genau eins von beiden.
 *  @param {{ datei?: string, key?: object|string|Buffer, scopes: string[], fetchImpl?: typeof fetch }} p */
export async function getServiceAccountToken({ datei, key, scopes, fetchImpl = fetch }) {
  const q = schluesselQuelle({ datei, key }, 'getServiceAccountToken');
  if (!q || !scopes?.length) throw new Error(`getServiceAccountToken: ${key != null ? 'key' : 'datei'} und scopes sind Pflicht`);
  const scope = serviceAccountScopes(scopes.join(' '));
  const schluessel = `${q.id}|${scope}`;
  const c = eigeneScopes.get(schluessel);
  if (c && c.expiresAt > Date.now() + 60_000) return c.accessToken;
  const json = await serviceAccountToken(q, { scope }, fetchImpl);
  eigeneScopes.set(schluessel, { accessToken: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000 });
  return json.access_token;
}

// Diagnostic: which scopes did we actually get?
export async function getGrantedScopes() {
  const at = await getAccessToken();
  const res = await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + at);
  const json = await res.json();
  return json.scope || '';
}

const ausDatei = new Map();   // Pfad → { accessToken, expiresAt }

/**
 * Access-Token aus einer eigenen OAuth-Token-Datei (eigener Token je Postfach, z. B. nur
 * gmail.readonly): { refresh_token, client_id?, client_secret?, token_uri? }. Fehlen
 * client_id/client_secret, kommen sie aus oauth-client.json daneben. Teilt keinen Cache mit getAccessToken().
 *
 * allowedScopes: Liste der Scopes, die der Token höchstens haben darf. Gemessen wird, was Google beim Refresh
 * meldet (nicht das scopes-Feld der Datei). Hat er mehr (z. B. versehentlich token.json des Inhabers als token_file),
 * Fehler statt Lauf: ein Lese-Job bekommt so nie einen Generalschlüssel. Ohne Angabe keine Prüfung (wie bisher).
 */
export async function getAccessTokenFromFile(datei, { allowedScopes = null, fetchImpl = fetch } = {}) {
  const pruefe = (granted) => {
    if (!allowedScopes) return;
    if (!granted) throw new Error(`Token-Datei ${datei}: Google meldet keine Scopes, Rechte nicht prüfbar`);
    const extra = granted.split(' ').filter((s) => s && !allowedScopes.includes(s));
    if (extra.length) throw new Error(`Token-Datei ${datei} hat andere Rechte als erlaubt (${extra.join(', ')}); erlaubt nur: ${allowedScopes.join(', ')}`);
  };
  const c = ausDatei.get(datei);
  if (c && c.expiresAt > Date.now() + 60_000) { pruefe(c.scope); return c.accessToken; }
  let token;
  // Nie den Dateiinhalt in eine Fehlermeldung (Refresh-Token).
  try { token = JSON.parse(readFileSync(datei, 'utf8')); } catch (e) { throw new Error(`Token-Datei ${datei} nicht lesbar (${e.code ?? 'kein gültiges JSON'})`); }
  if (!token.refresh_token) throw new Error(`Token-Datei ${datei}: refresh_token fehlt`);
  let { client_id: clientId, client_secret: clientSecret } = token;
  if (!clientId || !clientSecret) {
    let oc;
    // Auch hier nie den Dateiinhalt in eine Meldung (Client-Secret).
    try { oc = JSON.parse(readFileSync(join(configDir(), 'oauth-client.json'), 'utf8')); } catch (e) { throw new Error(`oauth-client.json nicht lesbar (${e.code ?? 'kein gültiges JSON'})`); }
    const w = oc.installed || oc.web || oc;
    clientId ||= w.client_id;
    clientSecret ||= w.client_secret;
  }
  const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, refresh_token: token.refresh_token, grant_type: 'refresh_token' });
  let res;
  try {
    res = await fetchImpl(token.token_uri || 'https://oauth2.googleapis.com/token', { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  } catch (e) { throw new Error(`Google-Anmeldung mit ${datei}: Token-Endpunkt ${netzGrund(e)}`); }
  const json = await tokenJson(res, `Google-Anmeldung mit ${datei}`);
  if (!res.ok) throw new Error(`Google-Anmeldung mit ${datei} fehlgeschlagen: ${fehlerText(json) || res.status}`);
  pruefe(json.scope);
  ausDatei.set(datei, { accessToken: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000, scope: json.scope ?? null });
  return json.access_token;
}
