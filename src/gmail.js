// Gmail-Zugang mit Wächter (access-client). Legt nur ENTWÜRFE an und sendet nie: Senden macht ein Mensch in Gmail.
// Lesen nur über feste GET-Pfade; Sicherheitsmails (ein konfiguriertes Label, siehe configureGmailGuard) gesperrt.
// Keine Fremd-Abhängigkeiten (Node ≥ 22, natives fetch).

import { getAccessToken } from './google-auth.js';

// ---------------------------------------------------------------------------------------------
// Versand-Sperre: die Entwurfs-Regel im Code erzwingen.
//
// Scope für Entwürfe. Achtung: Laut Google-Doku (Authorization scopes, Stand 19.10.2026) erlaubt
// gmail.compose auch das Senden, über drafts.send und messages.send; dasselbe gilt für gmail.modify und
// https://mail.google.com/. Einen Scope „nur Entwürfe“ gibt es nicht. Gewählt ist er trotzdem, weil
// drafts.create und drafts.update ihn brauchen.
// Senden ist deshalb im Code gesperrt, nicht über den Scope: jeder Gmail-Aufruf aus diesem Modul läuft
// durch assertNoSend(), und test/gmail-send-guard.test.mjs verbietet Versand-Endpunkte im ganzen Paket.
// Versand nur per Klick eines Menschen in Gmail.
export const GMAIL_COMPOSE = 'https://www.googleapis.com/auth/gmail.compose';

const GMAIL_USERS = 'https://gmail.googleapis.com/gmail/v1/users/';
/** Text der Versand-Sperre, solange der Aufrufer keinen eigenen setzt (configureGmailGuard sendBlockedReason). */
export const SEND_BLOCKED_DEFAULT = 'Versand gesperrt, nur Entwürfe (Senden macht ein Mensch in Gmail)';

// Einmalige Konfiguration des Wächters je Prozess (Sperr-Label für Sicherheitsmails, Text der Versand-Sperre). Die
// Werte gehören dem nutzenden Repo, nicht dem Paket. Ein zweiter Aufruf mit anderen Werten wirft: Kein Modul kann
// die Sperre eines anderen still umstellen. Ohne Sperr-Label liest kein Inhaltspfad (fail-closed).
let guard = null;
const LABEL_RE = /^[a-z0-9-]{3,40}$/;

/**
 * @param {{ blockedLabel: string, sendBlockedReason?: string, requireLabel?: boolean }} cfg  blockedLabel normalisiert
 *   (klein, „-“ statt Leerzeichen), so wie Gmail es in der Suche schreibt (label:<name>). requireLabel: Fehlt das Label
 *   im Postfach, liest kein Inhaltspfad (sonst nur eine Warnung im Log und weiterlesen, wie bisher für Jobs).
 * @returns {{ blockedLabel: string, sendBlockedReason: string, requireLabel: boolean }}
 */
export function configureGmailGuard({ blockedLabel, sendBlockedReason = SEND_BLOCKED_DEFAULT, requireLabel = false } = {}) {
  if (typeof blockedLabel !== 'string' || !LABEL_RE.test(blockedLabel)) throw new Error('configureGmailGuard: blockedLabel fehlt oder ist ungültig (a–z, 0–9, „-“, 3–40 Zeichen)');
  if (typeof sendBlockedReason !== 'string' || sendBlockedReason.length < 5 || sendBlockedReason.length > 200 || /[\r\n]/.test(sendBlockedReason)) throw new Error('configureGmailGuard: sendBlockedReason muss eine Zeile mit 5–200 Zeichen sein');
  if (typeof requireLabel !== 'boolean') throw new Error('configureGmailGuard: requireLabel muss true oder false sein');
  const neu = Object.freeze({ blockedLabel, sendBlockedReason, requireLabel });
  if (guard && (guard.blockedLabel !== neu.blockedLabel || guard.sendBlockedReason !== neu.sendBlockedReason || guard.requireLabel !== neu.requireLabel)) {
    throw new Error('configureGmailGuard: Wächter ist in diesem Prozess schon anders konfiguriert');
  }
  guard ??= neu;
  return guard;
}
/** Aktuelle Konfiguration oder null. */
export const gmailGuardConfig = () => guard;
function blockedLabel() {
  if (!guard) throw new GmailReadError('Gmail: Sperr-Label für Sicherheitsmails nicht konfiguriert (configureGmailGuard); nichts gelesen');
  return guard.blockedLabel;
}

export class GmailSendBlockedError extends Error {
  constructor(detail) { super(`Gmail: ${guard?.sendBlockedReason ?? SEND_BLOCKED_DEFAULT}. Abgelehnt: ${String(detail).slice(0, 120)}`); this.name = 'GmailSendBlockedError'; }
}

/**
 * Wirft, wenn ein Pfad (relativ zu users/<Postfach>/) zu einem Versand-Endpunkt führen könnte: ein Pfadteil
 * „send“ oder „sendAs“, auch URL-kodiert oder in anderer Schreibweise, Pfade mit „..“ oder eine volle URL.
 * Prüft den Pfad so, wie er gebaut wurde, damit auch dynamisch zusammengesetzte Pfade nicht durchrutschen.
 */
export function assertNoSend(path) {
  const raw = String(path ?? '');
  let decoded = raw;
  // Mehrfach kodiert (%252F) zählt auch: bis zu drei Runden dekodieren; was sich nicht dekodieren lässt, ist verdächtig.
  for (let i = 0; i < 3; i++) {
    let next;
    try { next = decodeURIComponent(decoded); } catch { throw new GmailSendBlockedError(`${raw} (nicht dekodierbar)`); }
    if (next === decoded) break;
    decoded = next;
  }
  const p = decoded.toLowerCase();
  if (/[a-z][a-z0-9+.-]*:\/\//.test(p) || p.startsWith('/') || /(^|[/\\])\.\.([/\\]|$)/.test(p)) throw new GmailSendBlockedError(`${raw} (nur relative Pfade)`);
  const segments = p.split(/[/\\?#:;]/);
  if (segments.some((s) => s === 'send' || s.startsWith('sendas'))) throw new GmailSendBlockedError(raw);
  return raw;
}

// Schreibende Pfade: nur Entwürfe anlegen (drafts) und ändern (drafts/<id>). Alles andere ist ein neuer
// Zweck und braucht eine bewusste Änderung hier, nicht nur einen neuen Aufruf.
const WRITE_PATH = /^drafts(\/[A-Za-z0-9_-]+)?$/;
const WRITE_METHODS = new Set(['POST', 'PUT']);

/**
 * Die gemeinsame Hülle für schreibende Gmail-Aufrufe (createDraft, ein künftiges updateDraft per PUT drafts/<id>).
 * Lehnt Versand-Pfade ab, bevor irgendetwas gesendet wird, und erlaubt nur die Entwurfs-Pfade.
 * @returns {Promise<Response>} die rohe Antwort; Fehlerbehandlung macht der Aufrufer.
 */
export async function gmailPost({ token, mailbox = 'me', path, body, method = 'POST', fetchImpl = fetch, timeoutMs = 30_000 }) {
  assertNoSend(path);
  assertNoSend(mailbox);
  const m = String(method).toUpperCase();
  if (!WRITE_METHODS.has(m)) throw new Error(`Gmail: Methode ${m} nicht erlaubt (nur POST/PUT für Entwürfe)`);
  if (!WRITE_PATH.test(String(path))) throw new Error(`Gmail: schreibender Pfad „${String(path).slice(0, 80)}“ nicht erlaubt (nur drafts, drafts/<id>)`);
  if (!token) throw new Error('Gmail: kein Zugangstoken');
  const url = `${GMAIL_USERS}${encodeURIComponent(mailbox)}/${path}`;
  return fetchImpl(url, {
    method: m,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
}

// RFC 2047 encode a header value only if it contains non-ASCII.
function encodeHeader(value) {
  // eslint-disable-next-line no-control-regex
  if (/^[\x00-\x7F]*$/.test(value)) return value;
  return '=?UTF-8?B?' + Buffer.from(value, 'utf8').toString('base64') + '?=';
}

// cc: string oder Array; leere Werte werden verworfen, damit kein "Cc: " entsteht.
export function normalizeCc(cc) {
  const list = Array.isArray(cc) ? cc : String(cc || '').split(/[,;]/);
  return list.map((e) => String(e || '').trim()).filter(Boolean);
}

/** Message-ID-Liste für In-Reply-To/References: nur `<…>`-Werte ohne Zeilenumbruch (keine Kopfzeilen-Injektion). */
const MSGID_RE = /^<[^<>\s\r\n]{3,250}>$/;
export function msgIdList(v) {
  const ids = String(v ?? '').split(/\s+/).filter(Boolean);
  return ids.filter((x) => MSGID_RE.test(x)).slice(-20).join(' ');
}

/**
 * MIME einer HTML-Mail. `reply`: { inReplyTo, references } für eine Antwort im selben Gmail-Thread (RFC 2822
 * In-Reply-To/References); ungültige Werte fallen still weg.
 */
export function buildMime(to, subject, htmlBody, cc, reply = null) {
  const body64 = Buffer.from(htmlBody, 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n');
  const ccList = normalizeCc(cc);
  const headers = [`To: ${to}`];
  if (ccList.length) headers.push(`Cc: ${ccList.join(', ')}`);
  const irt = msgIdList(reply?.inReplyTo).split(' ').at(-1);
  if (irt) headers.push(`In-Reply-To: ${irt}`);
  const refs = msgIdList(reply?.references);
  if (refs) headers.push(`References: ${refs}`);
  headers.push(
    `Subject: ${encodeHeader(subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset="UTF-8"',
    'Content-Transfer-Encoding: base64',
  );
  return headers.join('\r\n') + '\r\n\r\n' + body64;
}

// base64url of the full raw MIME message
function toRaw(mime) {
  return Buffer.from(mime, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Entwurf anlegen (nie senden), über die Hülle gmailPost. `opts` nur für Tests und eigene Tokens. */
export async function createDraft(to, subject, htmlBody, cc, { token, fetchImpl } = {}) {
  const at = token ?? await getAccessToken();
  const raw = toRaw(buildMime(to, subject, htmlBody, cc));
  const res = await gmailPost({ token: at, path: 'drafts', body: { message: { raw } }, fetchImpl });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Gmail API ${res.status}: ${JSON.stringify(json.error || json)}`);
  }
  return json.id; // draft id
}

/**
 * Entwurf mit Profil-Prüfung (Weg für neue Aufrufer): Erst liest getProfile, zu welchem Postfach der Token gehört;
 * nur wenn das genau `expectedMailbox` ist, entsteht EIN Entwurf in genau diesem Postfach. Kein Senden, kein Retry:
 * Antwortet Gmail beim Anlegen mit 5xx oder bricht die Verbindung ab, kann der Entwurf trotzdem entstanden sein; ein
 * zweiter Versuch ergäbe dann zwei Entwürfe. Der Fehler sagt das, der Aufrufer prüft im Postfach statt zu wiederholen.
 * @returns {Promise<{ draftId: string, messageId: string|null, threadId: string|null, mailbox: string }>}
 */
export async function createCheckedDraft({ token, expectedMailbox, to, subject, html, cc, reply = null, fetchImpl = fetch }) {
  const want = String(expectedMailbox ?? '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/.test(want)) throw new Error('Gmail-Entwurf: expectedMailbox (volle Adresse des Postfachs) fehlt');
  if (!to || !subject || typeof html !== 'string') throw new Error('Gmail-Entwurf: to, subject und html sind Pflicht');
  // Kein Zeilenumbruch in Kopfzeilen: sonst entstünden fremde Kopfzeilen im Entwurf (z. B. ein Bcc aus dem Betreff).
  for (const [feld, wert] of [['to', to], ['subject', subject], ...normalizeCc(cc).map((c) => ['cc', c])]) {
    if (/[\r\n]/.test(String(wert))) throw new Error(`Gmail-Entwurf: Zeilenumbruch in ${feld}; nichts angelegt`);
  }
  const profil = await getProfile({ token, mailbox: want, fetchImpl });
  const ist = String(profil?.emailAddress ?? '').toLowerCase();
  if (ist !== want) throw new Error(`Gmail-Entwurf: Token gehört zu ${ist || 'unbekannt'}, erwartet ${want}; nichts angelegt`);
  const raw = toRaw(buildMime(to, subject, html, cc, reply));
  let res;
  try {
    res = await gmailPost({ token, mailbox: want, path: 'drafts', body: { message: { raw, ...(reply?.threadId ? { threadId: String(reply.threadId) } : {}) } }, fetchImpl });
  } catch (e) {
    if (e instanceof GmailSendBlockedError) throw e;
    throw new Error(`Gmail-Entwurf: Verbindung abgebrochen (${e?.cause?.code ?? e?.name ?? 'Fehler'}); Entwurf evtl. angelegt, im Postfach prüfen, NICHT wiederholen`);
  }
  const json = await res.json().catch(() => ({}));
  if (res.status >= 500) throw new Error(`Gmail-Entwurf: API ${res.status}; Entwurf evtl. angelegt, im Postfach prüfen, NICHT wiederholen`);
  if (!res.ok) throw new Error(`Gmail-Entwurf: API ${res.status}: ${String(json?.error?.message ?? '').slice(0, 200)}`);
  if (typeof json?.id !== 'string') throw new Error('Gmail-Entwurf: Antwort ohne Entwurfs-ID; im Postfach prüfen, NICHT wiederholen');
  return { draftId: json.id, messageId: json.message?.id ?? null, threadId: json.message?.threadId ?? null, mailbox: want };
}

// ---------------------------------------------------------------------------------------------
// Lesen. NUR GET-Aufrufe: Profil, Labels, Nachrichtenliste, eine Nachricht, ein Verlauf, ein Anhang.
// Der Token wird übergeben (Inhaber-Token, eigene Token-Datei oder delegiertes Dienstkonto); hier wird nichts
// gesendet, verschoben, gelabelt oder gelöscht.
// Mailinhalte sind fremder Text: diese Funktionen liefern sie nur als Daten zurück.

export const GMAIL_READONLY = 'https://www.googleapis.com/auth/gmail.readonly';
/** Scopes, mit denen Inhalte lesbar sind (gmail.metadata reicht nicht: keine Texte, keine Suche). */
export const GMAIL_READ_SCOPES = Object.freeze([GMAIL_READONLY, 'https://www.googleapis.com/auth/gmail.modify', 'https://mail.google.com/']);

export class GmailReadError extends Error {
  constructor(message, { status = null, scope = false } = {}) { super(message); this.status = status; this.scope = scope; }
}

// ---------------------------------------------------------------------------------------------
// Sicherheitsmails gesperrt. Mails mit dem konfigurierten Sperr-Label (Passwort-Reset, Login-Codes, 2FA; gesetzt von
// einem Gmail-Filter im Postfach) liest kein Lesepfad dieses Moduls:
// - nur feste Lesepfade (profile, labels, messages, messages/<id>, messages/<id>/attachments/<id>, threads/<id>),
//   nichts mit ?/# im Pfad; die Thread-Liste (sie trägt Auszüge) gibt es nicht;
// - VOR jedem Inhaltsabruf prüft ein eigener Abruf mit format=minimal die Labels der Mail bzw. aller Mails des
//   Verlaufs (vom Aufrufer nicht beschränkbar, `fields` wirkt dort nicht); fehlen die Labels in der Antwort: Fehler;
// - jede Suche bekommt `-label:<name>` (Anfrage geklammert); die Liste trägt nur IDs, deren Inhalt wieder geprüft wird;
// - gesperrt sind ALLE Labels, deren Name normalisiert gleich ist (Gmail sucht „No Read“ wie „no-read“);
// - sind die Labels des Postfachs nicht lesbar: nichts gelesen. Fehlt das Label: WARNUNG im Log, nicht gecacht
//   (ein neu angelegtes Label wirkt sofort); gefundene IDs gelten 60 s, je Postfach UND Token (Kontoinhaber).
// Labelname und die Absenderliste der einen Ausnahme (readPortalCodeMails) gehören dem Aufrufer: das Label über
// configureGmailGuard, die Absender als Pflichtparameter codeMailSenders.
const BLOCKED_TTL_MS = 60_000;
// So weit wie die Gmail-Suche selbst: Groß-/Kleinschreibung egal, Leerzeichen im Labelnamen sucht Gmail als Bindestrich
// („No Read“ ⇔ label:no-read). Nicht weiter, sonst sperrte die ID-Prüfung, was die Suche nicht ausschließt, und ein
// Job scheiterte an einer Mail aus der eigenen Trefferliste.
export const labelKey = (n) => String(n ?? '').trim().toLowerCase().replace(/\s+/g, '-');
const blockedCache = new WeakMap(); // fetchImpl → Map(`${mailbox}\0${token}` → { ids, until })
const warnedMissing = new Set();
const READ_PATH = /^(profile|labels|messages|messages\/[A-Za-z0-9_-]+|messages\/[A-Za-z0-9_-]+\/attachments\/[A-Za-z0-9_-]+|threads\/[A-Za-z0-9_-]+)$/;
const MISSING_TTL_MS = 20_000; // „Label fehlt“ nur kurz merken (spart Abrufe, ein neues Label wirkt nach höchstens 20 s)

/** Suchanfrage mit unausgeglichenen Klammern oder Anführungszeichen könnte den Ausschluss aus der Klammer lösen. */
export function assertBalancedQuery(q) {
  // Klammern zählen auch in Anführungszeichen: Ob Gmail ein " mitten im Wort als Zitat liest, ist nicht
  // belegt. So hält die Prüfung unter beiden Annahmen; der Preis ist, dass `subject:"a (b"` abgelehnt wird.
  let rund = 0; let geschweift = 0; let quotes = 0;
  for (const ch of String(q ?? '')) {
    if (ch === '"') quotes++;
    else if (ch === '(') rund++; else if (ch === ')') rund--; else if (ch === '{') geschweift++; else if (ch === '}') geschweift--;
    if (rund < 0 || geschweift < 0) break;
  }
  if (quotes % 2 || rund !== 0 || geschweift !== 0) throw new GmailReadError('Gmail-Suche: Klammern oder Anführungszeichen nicht ausgeglichen (Sperre für Sicherheitsmails)');
}

export class GmailBlockedError extends GmailReadError {
  constructor(message) { super(message, { status: 403 }); this.blocked = true; }
}

/**
 * Label-Stand des Postfachs: IDs aller Sperr-Labels (leer = Label fehlt) und alle bekannten Label-IDs. Nicht lesbar →
 * Fehler, nie „keine Sperre“. force: Cache übergehen (eine Mail trägt eine Label-ID, die der Cache nicht kennt, z. B.
 * weil das Sperr-Label gelöscht und neu angelegt wurde oder während des 20-s-Fensters „fehlt“ entstand).
 */
async function labelState({ token, mailbox, fetchImpl, timeoutMs, force = false }) {
  const label = blockedLabel();
  let m = blockedCache.get(fetchImpl);
  if (!m) { m = new Map(); blockedCache.set(fetchImpl, m); }
  const key = `${label}\0${mailbox}\0${token}`;
  const c = m.get(key);
  const streng = (st) => {
    if (!st.ids.length && guard.requireLabel) {
      throw new GmailReadError(`Gmail: Sperr-Label ${label} fehlt im Postfach ${mailbox}; Sicherheitsmails nicht ausschließbar, nichts gelesen (Gmail-Filter anlegen)`);
    }
    return st;
  };
  if (!force && c && Date.now() < c.until) return streng(c);
  const l = await rawGet({ token, mailbox, path: 'labels', fetchImpl, timeoutMs });
  if (!Array.isArray(l.labels)) throw new GmailReadError('Gmail: Labels nicht lesbar; Sperre für Sicherheitsmails nicht prüfbar, nichts gelesen');
  const ids = l.labels.filter((x) => labelKey(x?.name) === label && typeof x?.id === 'string' && x.id).map((x) => x.id);
  const known = new Set(l.labels.map((x) => x?.id).filter((x) => typeof x === 'string'));
  const state = { ids, known, until: Date.now() + (ids.length ? BLOCKED_TTL_MS : MISSING_TTL_MS) };
  m.set(key, state);
  streng(state);
  if (!ids.length && !warnedMissing.has(mailbox)) {
    warnedMissing.add(mailbox);
    console.warn(`WARNUNG Gmail: Label ${label} fehlt im Postfach ${mailbox}; Sicherheitsmails sind NICHT ausgeschlossen (Gmail-Filter anlegen)`);
  }
  return state;
}
/** Labels einer Mail bzw. aller Mails eines Verlaufs aus einer minimal-Antwort; fehlt etwas: Fehler (fail-closed). */
function labelsOfMinimal(j, what) {
  const msgs = what === 'thread' ? j?.messages : [j];
  if (!Array.isArray(msgs) || !msgs.length || msgs.some((x) => !Array.isArray(x?.labelIds) && x?.labelIds !== undefined)) {
    throw new GmailReadError(`Gmail: Labels ${what === 'thread' ? 'des Verlaufs' : 'der Mail'} nicht lesbar; nichts gelesen`);
  }
  // Gmail lässt labelIds weg, wenn eine Mail gar kein Label trägt; das ist „keins“, nicht „unbekannt“
  return msgs.flatMap((x) => x.labelIds ?? []);
}
/** Prüft Label-IDs gegen den Stand; kennt der Stand eine ID nicht, wird er frisch geholt. Gibt den Stand zurück. */
async function checkLabels(labels, state, o, what) {
  let st = state;
  if (labels.some((l) => !st.known.has(l))) {
    st = await labelState({ ...o, force: true });
    // Was auch der frische Stand nicht kennt, ist belegt kein Sperr-Label: merken, sonst holte jede Mail mit einer
    // solchen ID den Stand erneut (zwei Abrufe mehr je Inhaltsabruf).
    for (const l of labels) st.known.add(l);
  }
  if (labels.some((l) => st.ids.includes(l))) {
    throw new GmailBlockedError(`Gmail: ${what === 'thread' ? 'Verlauf enthält eine Mail' : 'Mail'} mit Label ${blockedLabel()} (Sicherheitsmail); gesperrt`);
  }
  return st;
}
async function assertNotBlocked({ token, mailbox, fetchImpl, timeoutMs, state, kind, id }) {
  // Auch ohne gefundenes Sperr-Label: Der Prüfabruf zeigt, ob die Mail ein Label trägt, das der Stand nicht kennt.
  const j = await rawGet({ token, mailbox, path: `${kind === 'thread' ? 'threads' : 'messages'}/${id}`, params: { format: 'minimal' }, fetchImpl, timeoutMs });
  if (String(j?.id) !== decodeURIComponent(id)) throw new GmailReadError(`Gmail: Prüfabruf ${kind === 'thread' ? 'Verlauf' : 'Mail'} unvollständig; nichts gelesen`);
  return checkLabels(labelsOfMinimal(j, kind), state, { token, mailbox, fetchImpl, timeoutMs }, kind);
}

/**
 * GET auf die Gmail-API für genau ein Postfach. `params` als Objekt; Listenwerte werden wiederholt angehängt.
 * Nur feste Lesepfade, mit Sperre für Sicherheitsmails (oben); `labels` und `profile` gehen unverändert durch.
 */
export async function gmailGet({ token, mailbox, path, params = {}, fetchImpl = fetch, timeoutMs = 20_000 }) {
  if (!token) throw new GmailReadError('Gmail: kein Zugangstoken');
  assertNoSend(path);
  assertNoSend(mailbox);
  const p = String(path);
  if (!READ_PATH.test(p)) throw new GmailReadError(`Gmail: Lesepfad ${p.replace(/[^A-Za-z0-9/_-]/g, '').slice(0, 60)} nicht erlaubt`);
  if (p === 'labels' || p === 'profile') return rawGet({ token, mailbox, path, params, fetchImpl, timeoutMs });
  let state = await labelState({ token, mailbox, fetchImpl, timeoutMs });
  if (p === 'messages') {
    assertBalancedQuery(params.q);
    return rawGet({ token, mailbox, path, params: { ...params, q: `${params.q ? `(${params.q}) ` : ''}-label:${blockedLabel()}` }, fetchImpl, timeoutMs });
  }
  const [, kind, id] = /^(messages|threads)\/([^/]+)/.exec(p);
  const what = kind === 'threads' ? 'thread' : 'message';
  state = await assertNotBlocked({ token, mailbox, fetchImpl, timeoutMs, state, kind: what, id });
  const j = await rawGet({ token, mailbox, path, params, fetchImpl, timeoutMs });
  // zweite Prüfung am Ergebnis (falls die Labels sich dazwischen geändert haben), soweit die Antwort sie trägt
  if (!p.includes('/attachments/')) {
    const ls = [...(Array.isArray(j?.labelIds) ? j.labelIds : []), ...(Array.isArray(j?.messages) ? j.messages.flatMap((x) => (Array.isArray(x?.labelIds) ? x.labelIds : [])) : [])];
    await checkLabels(ls, state, { token, mailbox, fetchImpl, timeoutMs }, what);
  }
  return j;
}

// ---------------------------------------------------------------------------------------------
// AUSNAHME zur Sperre, genau eine: Ein Portal-Login, der Einmal-Codes per Mail bekommt, liest diese Codes gerade aus
// Sicherheitsmails. Er darf das nur hierüber:
// - Absender fest aus der Konfiguration des Aufrufers (codeMailSenders; Domain, genau oder Subdomain; geprüft am
//   From-Kopf, nicht nur an der Suche);
// - nur Mails der letzten 20 Minuten (internalDate), höchstens 10;
// - Inhalt nur für Mails, die beides erfüllen; alle anderen werden nicht geöffnet;
// - der Wert bleibt im Prozess (der Aufrufer loggt ihn nicht, er geht nicht ans Modell).
// Dass kein anderer Aufrufer sie nutzt, prüft der Test des aufrufenden Repos.
export const CODE_MAIL_WINDOW_MS = 20 * 60_000;
const hostOfFrom = (from) => {
  if ((String(from ?? '').match(/@/g) ?? []).length !== 1) return null; // mehrere Adressen: nie raten
  const m = /<([^<>\s]+@[^<>\s]+)>\s*$/.exec(String(from ?? '')) ?? /^\s*([^<>\s]+@[^<>\s]+)\s*$/.exec(String(from ?? ''));
  return m ? m[1].split('@').pop().toLowerCase() : null;
};
export async function readPortalCodeMails({ token, mailbox, senderDomain, codeMailSenders, fetchImpl = fetch, timeoutMs = 20_000 }) {
  if (!token) throw new GmailReadError('Gmail: kein Zugangstoken');
  assertNoSend(mailbox);
  if (!Array.isArray(codeMailSenders) || !codeMailSenders.length || codeMailSenders.some((d) => typeof d !== 'string' || !d)) {
    throw new GmailReadError('Code-Mail: codeMailSenders (Liste der erlaubten Absender-Domains aus der Konfiguration des Aufrufers) fehlt');
  }
  const dom = String(senderDomain ?? '').toLowerCase();
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(dom)) throw new GmailReadError('Code-Mail: Absender-Domain aus der Portal-Konfiguration fehlt oder ist ungültig');
  if (!codeMailSenders.map((d) => d.toLowerCase()).includes(dom)) throw new GmailReadError('Code-Mail: Absender-Domain steht nicht in codeMailSenders (Konfiguration des Aufrufers)');
  const page = await rawGet({ token, mailbox, path: 'messages', params: { q: `from:${dom} newer_than:1d`, maxResults: 10 }, fetchImpl, timeoutMs });
  if (page.messages !== undefined && !Array.isArray(page.messages)) throw new GmailReadError('Gmail-Nachrichtenliste ohne Liste');
  const grenze = Date.now() - CODE_MAIL_WINDOW_MS;
  const out = [];
  for (const m of page.messages ?? []) {
    if (typeof m?.id !== 'string' || !/^[A-Za-z0-9_-]+$/.test(m.id)) continue;
    const meta = await rawGet({ token, mailbox, path: `messages/${m.id}`, params: { format: 'metadata', metadataHeaders: ['From'] }, fetchImpl, timeoutMs });
    const host = hostOfFrom(headerOf(meta, 'From'));
    if (meta.id !== m.id || !(Number(meta.internalDate) >= grenze) || !host || !(host === dom || host.endsWith(`.${dom}`))) continue;
    const full = await rawGet({ token, mailbox, path: `messages/${m.id}`, params: { format: 'full' }, fetchImpl, timeoutMs });
    if (full.id !== m.id || typeof full.payload !== 'object' || full.payload === null) throw new GmailReadError('Code-Mail: Antwort unvollständig');
    out.push(full);
  }
  return { messages: out, truncated: Boolean(page.nextPageToken) };
}

async function rawGet({ token, mailbox, path, params = {}, fetchImpl = fetch, timeoutMs = 20_000 }) {
  if (!token) throw new GmailReadError('Gmail: kein Zugangstoken');
  assertNoSend(path);
  assertNoSend(mailbox);
  const u = new URL(`https://gmail.googleapis.com/gmail/v1/users/${encodeURIComponent(mailbox)}/${path}`);
  for (const [k, v] of Object.entries(params)) {
    if (v == null) continue;
    for (const x of Array.isArray(v) ? v : [v]) u.searchParams.append(k, String(x));
  }
  let res;
  try {
    res = await fetchImpl(u.href, { method: 'GET', headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new GmailReadError(`Gmail nicht erreichbar: ${e?.cause?.code ?? e?.name ?? 'Fehler'}`);
  }
  // Ein Abbruch NACH den Kopfzeilen (Timeout, Verbindung) ist ein Fehler, nie eine leere Antwort:
  // sonst sähe eine abgebrochene Liste aus wie „keine neuen Mails“ und die Zeitgrenze rückte vor.
  let json = null;
  let bodyError = null;
  try { json = await res.json(); } catch (e) { bodyError = e?.name === 'SyntaxError' ? 'kein JSON' : (e?.cause?.code ?? e?.name ?? 'Abbruch'); }
  if (!res.ok) {
    const msg = String(json?.error?.message ?? res.status).slice(0, 200);
    const scope = res.status === 403 && /insufficient|scope|permission/i.test(msg);
    throw new GmailReadError(`Gmail API ${res.status}: ${msg}`, { status: res.status, scope });
  }
  if (bodyError || !json || typeof json !== 'object' || Array.isArray(json)) {
    throw new GmailReadError(`Gmail-Antwort unvollständig (${bodyError ?? 'kein Objekt'})`, { status: res.status });
  }
  return json;
}

/** Profil des Postfachs (emailAddress, historyId): prüft, dass der Token wirklich zu diesem Postfach gehört. */
export const getProfile = ({ token, mailbox, fetchImpl }) => gmailGet({ token, mailbox, path: 'profile', fetchImpl });

/** Nachrichten-IDs zur Suche `q`, höchstens `max` (neueste zuerst, wie Gmail sie liefert). */
export async function listMessageIds({ token, mailbox, q, max = 300, fetchImpl }) {
  const ids = [];
  let pageToken;
  do {
    const page = await gmailGet({ token, mailbox, path: 'messages', params: { q, maxResults: Math.min(100, max - ids.length), pageToken }, fetchImpl });
    if (page.messages !== undefined && !Array.isArray(page.messages)) throw new GmailReadError('Gmail-Nachrichtenliste ohne Liste');
    const msgs = page.messages ?? [];
    if (msgs.some((m) => typeof m?.id !== 'string' || typeof m?.threadId !== 'string')) throw new GmailReadError('Gmail-Nachrichtenliste: Eintrag ohne id/threadId');
    for (let i = 0; i < msgs.length; i++) {
      ids.push({ id: msgs[i].id, threadId: msgs[i].threadId });
      if (ids.length >= max) return { ids, truncated: Boolean(page.nextPageToken) || i < msgs.length - 1 };
    }
    pageToken = page.nextPageToken;
  } while (pageToken);
  return { ids, truncated: false };
}

export const READ_METADATA_HEADERS = Object.freeze(['From', 'To', 'Subject', 'Date', 'List-Unsubscribe', 'List-Id', 'Auto-Submitted', 'Precedence']);

/** Eine Nachricht: format 'metadata' (nur Kopfzeilen) oder 'full' (mit Text). Prüft den Aufbau grob. */
export async function getMessage({ token, mailbox, id, format = 'metadata', fetchImpl }) {
  const params = { format, ...(format === 'metadata' ? { metadataHeaders: READ_METADATA_HEADERS } : {}) };
  const msg = await gmailGet({ token, mailbox, path: `messages/${encodeURIComponent(id)}`, params, fetchImpl });
  if (msg.id !== id || typeof msg.payload !== 'object' || msg.payload === null) throw new GmailReadError(`Gmail-Nachricht ${String(id).slice(0, 40)}: Antwort unvollständig`);
  return msg;
}

/**
 * Kopfzeilen aller Nachrichten eines Threads (z. B. für einen Antwort-Entwurf im selben Thread). Nur lesend;
 * braucht einen Lese-Scope (gmail.readonly/modify), gmail.compose allein reicht nicht.
 * @returns {{ id, messages: [{ id, labelIds, headers }] }}
 */
export async function getThreadMeta({ token, mailbox, threadId, fetchImpl }) {
  const t = await gmailGet({ token, mailbox, path: `threads/${encodeURIComponent(threadId)}`, params: { format: 'metadata', metadataHeaders: ['Message-ID', 'References', 'Subject', 'From', 'To'] }, fetchImpl });
  if (t.id !== threadId || !Array.isArray(t.messages)) throw new GmailReadError(`Gmail-Thread ${String(threadId).slice(0, 40)}: Antwort unvollständig`);
  return t;
}

/** Wert einer Kopfzeile (erste Fundstelle, Groß-/Kleinschreibung egal). */
export const headerOf = (msg, name) => msg?.payload?.headers?.find((h) => String(h.name).toLowerCase() === name.toLowerCase())?.value ?? '';

/** Reine Mail-Adresse aus „Name <a@b>“ (Anzeigenamen in Anführungszeichen zuerst weg), klein geschrieben. */
export function emailOf(value) {
  const t = String(value ?? '').replace(/"[^"]*"/g, '');
  return (t.match(/<([^>]+)>/)?.[1] ?? t).trim().toLowerCase();
}

function decodePart(part) {
  const data = part?.body?.data;
  if (!data) return '';
  // Base64 ist ~4/3 so lang wie der Text: vor dem Dekodieren begrenzen.
  const buf = Buffer.from(String(data).slice(0, Math.ceil(PART_MAX * 4 / 3) + 4).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const ct = (part.headers ?? []).find((h) => String(h.name).toLowerCase() === 'content-type')?.value ?? part.mimeType ?? '';
  const charset = /charset="?([^";\s]+)"?/i.exec(ct)?.[1] ?? 'utf-8';
  try { return new TextDecoder(charset.toLowerCase()).decode(buf); } catch { return buf.toString('utf8'); }
}

/** Obergrenze für dekodierte Teile vor jeder Verarbeitung (Laufzeit). */
export const PART_MAX = 200_000;

const ENTITIES = { nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'" };
const BLOCK_END = new Set(['p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const DROP = ['script', 'style', 'head', 'blockquote'];

/**
 * HTML grob zu Text, in EINEM Durchlauf ohne Rückverfolgung (/<[^>]*>/g war bei vielen „<“ ohne „>“
 * quadratisch). Zitatblöcke (blockquote, ab gmail_quote) und script/style/head fallen weg, Zeilenumbrüche bleiben.
 * Fehlt ein schließendes „>“ oder Ende-Tag, endet der Text dort.
 */
export function htmlToText(html) {
  const src = String(html ?? '').slice(0, PART_MAX);
  const lower = src.toLowerCase();
  let out = '';
  let i = 0;
  while (i < src.length) {
    const lt = src.indexOf('<', i);
    if (lt === -1) { out += src.slice(i); break; }
    out += src.slice(i, lt);
    const gt = src.indexOf('>', lt + 1);
    if (gt === -1) break;
    const tag = lower.slice(lt + 1, gt);
    const name = /^\/?([a-z0-9]+)/.exec(tag)?.[1] ?? '';
    i = gt + 1;
    if (!tag.startsWith('/') && /class\s*=\s*"?[^">]*gmail_quote/.test(tag)) break;
    if (!tag.startsWith('/') && DROP.includes(name)) {
      const end = lower.indexOf(`</${name}`, i);
      if (end === -1) break;
      const close = src.indexOf('>', end);
      if (close === -1) break;
      i = close + 1;
      out += '\n';
      continue;
    }
    if (name === 'br' || (tag.startsWith('/') && BLOCK_END.has(name))) out += '\n';
    else out += ' ';
  }
  return out
    .replace(/&(nbsp|amp|lt|gt|quot|apos|#39);/gi, (_, e) => ENTITIES[e.toLowerCase()])
    .replace(/&#(\d{1,7});/g, (_, n) => { const c = Number(n); return c > 31 && c < 0x110000 ? String.fromCodePoint(c) : ' '; })
    .replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n');
}

/**
 * Text einer Nachricht (format 'full'): erster text/plain-Teil, sonst text/html als Text. Anhänge werden nie gelesen.
 * html = roher HTML-Teil (falls vorhanden, auch neben text/plain), z. B. für Link-Ziele, die der Text verliert.
 * @returns {{ text: string, source: 'plain'|'html'|'none', html: string|null, truncated: boolean }}
 */
export function messageText(msg) {
  const parts = [];
  const walk = (p, depth = 0) => {
    if (!p || depth > 8) return;
    if (p.filename) return; // Anhang
    if (Array.isArray(p.parts)) { for (const c of p.parts) walk(c, depth + 1); return; }
    parts.push(p);
  };
  walk(msg?.payload);
  // Leerer text/plain-Teil (manche Programme) → auf HTML zurückfallen.
  const plain = parts.find((p) => String(p.mimeType).toLowerCase() === 'text/plain' && decodePart(p).trim());
  const html = parts.find((p) => String(p.mimeType).toLowerCase() === 'text/html');
  const raw = html ? decodePart(html) : null;
  // truncated: der gewählte Teil war länger als PART_MAX und ist schon beim Dekodieren gekürzt
  const gekuerzt = (p) => String(p?.body?.data ?? '').length > Math.ceil(PART_MAX * 4 / 3) + 4;
  if (plain) return { text: decodePart(plain), source: 'plain', html: raw, truncated: gekuerzt(plain) };
  if (html) return { text: htmlToText(raw), source: 'html', html: raw, truncated: gekuerzt(html) };
  return { text: '', source: 'none', html: null, truncated: false };
}
