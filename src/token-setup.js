// Lese-Token (OAuth, nur Lese-Scopes) für ein Konto aus read.json erzeugen, z. B. Drive/Sheets/Docs des Inhabers
// (S137 „Mail-Wächter-Job live“, Folgearbeit S123: access-read meldete „token-read-<konto>.json fehlt“, ein Werkzeug
// dafür gab es nicht). Zwei Schritte, weil die Zustimmung im Browser des Inhabers passiert und die Sitzung keine
// Eingabe hat:
//   start  → Anmelde-URL (PKCE S256, offline, nur Lese-Scopes, login_hint) und Zwischenstand (state, verifier; 600)
//   finish → Code aus der Weiterleitungs-URL gegen Token tauschen; schreibt nur, wenn state passt, Google genau
//            Lese-Scopes meldet, ein refresh_token kommt und das Konto (id_token email) stimmt. Neue Datei 600, nie
//            überschreiben. Die Datei hält nur refresh_token, scope, token_uri (Client aus oauth-client.json).
// Die Weiterleitung geht an http://127.0.0.1:<port>/ (Desktop-Client, Loopback); dort lauscht nichts, der Browser
// zeigt „nicht erreichbar“, die Adresszeile enthält den einmaligen Code. Der Code allein ist ohne den Verifier aus dem
// Zwischenstand (nur auf dieser Maschine) wertlos und verfällt nach Minuten.
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { assertScopesWithin, netzGrund } from './google-auth.js';
import { READ_SCOPE } from './read/accounts.js';

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const REDIRECT_URI = 'http://127.0.0.1:8765/';
/** Genau das, was ein Lese-Token für Drive/Sheets/Docs braucht; Mail läuft über die Delegierung, nicht hierüber. */
export const READ_TOKEN_SCOPES = Object.freeze([READ_SCOPE.drive, READ_SCOPE.sheets, READ_SCOPE.docs,
  'https://www.googleapis.com/auth/userinfo.email', 'openid']);

const defaultStateDir = () => join(process.env.XDG_STATE_HOME || join(homedir(), '.local/state'), 'access-client');
const pendingFile = (stateDir, account) => join(stateDir, `read-token-${account.name}.json`);
const clientOf = (oc) => { const w = oc?.installed || oc?.web || oc; if (!w?.client_id) throw new Error('oauth-client.json ohne client_id'); return w; };
const b64url = (b) => Buffer.from(b).toString('base64url');

/** Neue Datei mit Rechten 600; wirft, wenn sie schon existiert (O_EXCL). */
function schreibeNeu(datei, inhalt) {
  const fd = openSync(datei, 'wx', 0o600);
  try { writeSync(fd, inhalt); } finally { closeSync(fd); }
}

function ziel(account, googleDir) {
  if (!account?.file || account.kind === 'delegated' || account.kind === 'mail-only') throw new Error(`Konto ${account?.name}: kein OAuth-Token-Konto (in read.json „token“ setzen)`);
  if (/^(token|oauth-client)\.json$/.test(account.file)) throw new Error(`${account.file} ist als Lese-Token gesperrt`);
  return join(googleDir, account.file);
}

/**
 * @param {{ name, email, file, kind }} account aus read.json (resolveAccount)
 * @param {{ googleDir: string, stateDir?: string, client: object, random?: (n:number)=>Buffer }} o
 * @returns {{ url: string, pending: string, target: string }}
 */
export function startReadToken(account, { googleDir, stateDir = defaultStateDir(), client, random = randomBytes }) {
  const target = ziel(account, googleDir);
  mkdirSync(googleDir, { recursive: true, mode: 0o700 });
  if (existsSync(target)) throw new Error(`${target} existiert schon; nie überschreiben (alte Datei erst selbst umbenennen)`);
  const { client_id: clientId } = clientOf(client);
  const state = b64url(random(24));
  const verifier = b64url(random(48));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const url = new URL(AUTH_URL);
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code', scope: READ_TOKEN_SCOPES.join(' '),
    access_type: 'offline', prompt: 'consent', include_granted_scopes: 'false', login_hint: account.email, state,
    code_challenge: challenge, code_challenge_method: 'S256' })) url.searchParams.set(k, v);
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const pending = pendingFile(stateDir, account);
  rmSync(pending, { force: true }); // ein neuer Start ersetzt einen alten (eigene Datei, nur state/verifier)
  schreibeNeu(pending, JSON.stringify({ account: account.name, email: account.email, state, verifier, redirectUri: REDIRECT_URI, at: new Date().toISOString() }));
  return { url: url.toString(), pending, target };
}

/**
 * @param {string} redirectUrl die Adresse aus der Browserzeile nach der Zustimmung
 * @returns {Promise<{ target: string, scope: string, email: string }>} ohne Token
 */
export async function finishReadToken(account, redirectUrl, { googleDir, stateDir = defaultStateDir(), client, fetchImpl = fetch }) {
  const target = ziel(account, googleDir);
  const pending = pendingFile(stateDir, account);
  let p;
  try { p = JSON.parse(readFileSync(pending, 'utf8')); } catch (e) { throw new Error(`kein Zwischenstand für ${account.name} (${e.code ?? 'ungültig'}): erst „start“`); }
  let u;
  try { u = new URL(String(redirectUrl).trim()); } catch { throw new Error('Weiterleitungs-URL nicht lesbar'); }
  if (u.searchParams.get('error')) throw new Error(`Google: ${u.searchParams.get('error').replace(/[^\w.-]/g, '').slice(0, 60)}`);
  if (u.searchParams.get('state') !== p.state) throw new Error('state passt nicht zum Zwischenstand (andere oder alte Anmeldung); nichts getauscht');
  const code = u.searchParams.get('code');
  if (!code) throw new Error('Weiterleitungs-URL ohne code');
  if (existsSync(target)) throw new Error(`${target} existiert schon; nie überschreiben`);
  const { client_id: clientId, client_secret: clientSecret } = clientOf(client);
  const body = new URLSearchParams({ code, client_id: clientId, ...(clientSecret ? { client_secret: clientSecret } : {}),
    redirect_uri: p.redirectUri, grant_type: 'authorization_code', code_verifier: p.verifier });
  let res;
  try { res = await fetchImpl(TOKEN_URL, { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(20_000) }); } catch (e) { throw new Error(`Token-Endpunkt ${netzGrund(e)}`); }
  let json;
  try { json = await res.json(); } catch { throw new Error(`Token-Endpunkt: Antwort kein JSON (HTTP ${res.status})`); }
  if (!res.ok) throw new Error(`Token-Tausch abgelehnt: ${String(json?.error ?? res.status).replace(/[^\w.-]/g, '').slice(0, 60)}`);
  const scope = typeof json.scope === 'string' ? json.scope.trim() : '';
  if (!scope) throw new Error('Google meldet keine Scopes; nichts geschrieben');
  assertScopesWithin(scope, READ_TOKEN_SCOPES, 'Lese-Token');
  for (const s of [READ_SCOPE.drive, READ_SCOPE.sheets]) if (!scope.split(/\s+/).includes(s)) throw new Error(`Zustimmung ohne ${s.split('/').pop()}; nichts geschrieben`);
  if (typeof json.refresh_token !== 'string' || !json.refresh_token) throw new Error('refresh_token fehlt (Zustimmung ohne „offline“?); nichts geschrieben');
  let email = '';
  try { email = String(JSON.parse(Buffer.from(String(json.id_token).split('.')[1], 'base64url').toString('utf8')).email ?? '').toLowerCase(); } catch { /* unten */ }
  if (email !== String(account.email).toLowerCase()) throw new Error(`Anmeldung mit anderem Konto (${email ? email.replace(/^[^@]*/, '…') : 'unbekannt'}) als ${account.email}; nichts geschrieben`);
  schreibeNeu(target, JSON.stringify({ refresh_token: json.refresh_token, scope, token_uri: TOKEN_URL }));
  rmSync(pending, { force: true });
  return { target, scope, email };
}
