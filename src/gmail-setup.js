// Sperr-Label für Sicherheitsmails in einem Postfach einrichten (S112 „Ein Mail-Weg für Sessions und Agenten“, Sascha
// 23.11.2026, Board A694 a). Label (z. B. security-no-read) und die zwei Gmail-Filter aus Unraid openclaw/README.md
// „Gmail-Filter für Sicherheitsmails“; der Gmail-Wächter (src/gmail.js, requireLabel) liest ein Postfach erst, wenn
// das Label dort existiert.
//
// Grenzen: nur GET labels / settings/filters und POST labels / settings/filters (Anlegen); für den Mail-Wächter
// zusätzlich GET auf Weiterleitungen, Delegierungen, IMAP und POP (readMailSettings). Kein Ändern, kein Löschen,
// kein Senden, keine Weiterleitung: die Filter-Aktion ist nur „Label anwenden“ (nicht Posteingang überspringen, Sascha
// sieht die Mails wie bisher). Idempotent: angelegt wird nur, was fehlt. Scopes: gmail.labels (Label) und
// gmail.settings.basic (Filter), je ein eigener Token.
//
// Gmail-Filter aus der API wirken nur auf NEUE Mails; vorhandene Sicherheitsmails bekommen das Label nicht (dafür
// bräuchte es gmail.modify). Das sagt die Ausgabe des Skripts.

import { assertNoSend, labelKey } from './gmail.js';
import { SENDER_QUERY, SUBJECT_QUERY } from './security-mail.js';

const USERS = 'https://gmail.googleapis.com/gmail/v1/users/';
export const GMAIL_LABELS = 'https://www.googleapis.com/auth/gmail.labels';
export const GMAIL_SETTINGS_BASIC = 'https://www.googleapis.com/auth/gmail.settings.basic';

// Filter aus der gemeinsamen Liste (src/security-mail.js), dieselbe, die der Wächter prüft.
export const SECURITY_FILTERS = Object.freeze([
  Object.freeze({ name: 'filter-betreff', criteria: Object.freeze({ query: SUBJECT_QUERY }) }),
  Object.freeze({ name: 'filter-absender', criteria: Object.freeze({ from: SENDER_QUERY }) }),
]);

const PFADE = new Set(['labels', 'settings/filters']);
// Nur lesend für den Mail-Wächter (S114): Weiterleitungen, Delegierungen, IMAP/POP; nie schreibend erreichbar.
// Nur Listen kommen leer, wenn sie leer sind (reviewer S114 nice 8); imap/pop/autoForwarding leer wäre ein Fehler.
// Abwesenheitsnotiz (S123, Board A800 a): mail-jobs kann sie setzen, sie erreicht Kunden. Absender-Einstellungen
// (Reply-To) liest readAbsender unten, die einzige Ausnahme zur Versand-Sperre.
const LISTEN = new Set(['settings/filters', 'settings/forwardingAddresses', 'settings/delegates']);
const NUR_LESEN = new Set(['settings/forwardingAddresses', 'settings/autoForwarding', 'settings/imap', 'settings/pop', 'settings/delegates',
  'settings/vacation']);
const MAILBOX = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;

async function call({ token, mailbox, path, method = 'GET', body, fetchImpl }) {
  if (!MAILBOX.test(String(mailbox))) throw new Error(`Gmail-Einrichtung: Postfach ${String(mailbox).slice(0, 60)} ungültig`);
  assertNoSend(path); assertNoSend(mailbox);
  const lesend = method === 'GET' && NUR_LESEN.has(path);
  if (!lesend && (!PFADE.has(path) || !['GET', 'POST'].includes(method))) throw new Error(`Gmail-Einrichtung: ${method} ${path} nicht erlaubt`);
  if (!token) throw new Error('Gmail-Einrichtung: kein Zugangstoken');
  let res;
  try {
    res = await fetchImpl(`${USERS}${encodeURIComponent(mailbox)}/${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30_000),
    });
  } catch (e) { throw new Error(`Gmail-Einrichtung: ${mailbox} nicht erreichbar (${e?.cause?.code ?? e?.name ?? 'Fehler'})`); }
  // Gmail antwortet auf settings/filters ohne Filter mit leerem Körper (gesehen 24.11.2026): das ist „keine Filter“.
  const roh = typeof res.text === 'function' ? await res.text().catch(() => null) : JSON.stringify(await res.json().catch(() => null));
  let j = null;
  // Leere Listen (Filter, Weiterleitungen, Delegierungen) kommen ebenso leer: auch „keine“.
  if (res.ok && method === 'GET' && LISTEN.has(path) && roh != null && roh.trim() === '') j = {};
  else { try { j = JSON.parse(roh); } catch { j = null; } }
  if (!res.ok) throw new Error(`Gmail-Einrichtung ${method} ${path} in ${mailbox}: API ${res.status} ${String(j?.error?.message ?? '').slice(0, 160)}`);
  if (!j || typeof j !== 'object') throw new Error(`Gmail-Einrichtung ${method} ${path}: Antwort unvollständig`);
  return j;
}

// Gleich nur, wenn der Filter GENAU dieses Kriterium hat: ein zusätzliches (to, subject, size, hasAttachment …) schränkt
// ihn ein und schützt dann nicht alle Mails (Codex S112 #2).
const norm = (c) => {
  const extra = Object.keys(c ?? {}).filter((k) => !['query', 'from'].includes(k) && c[k] !== false && c[k] !== '' && c[k] != null);
  return extra.length ? `eingeschränkt:${extra.join(',')}` : JSON.stringify({ query: String(c?.query ?? '').trim(), from: String(c?.from ?? '').trim().toLowerCase() });
};

/** Was von Label und Sicherheitsfiltern fehlt, aus gelesenen Labels und Filtern (auch für den Mail-Wächter). */
export function missingSecurityParts({ labels, filters, label, mailbox = 'Postfach' }) {
  const key = labelKey(label);
  const treffer = (labels ?? []).filter((l) => labelKey(l?.name) === key);
  if (treffer.length > 1) throw new Error(`Gmail-Einrichtung: ${mailbox} hat ${treffer.length} Labels namens ${label}; bitte von Hand bereinigen`);
  const labelId = treffer[0]?.id ?? null;
  const missing = [];
  if (!labelId) missing.push({ name: 'label' });
  for (const sf of SECURITY_FILTERS) {
    const da = labelId && (filters ?? []).some((x) => norm(x?.criteria) === norm(sf.criteria) && (x?.action?.addLabelIds ?? []).includes(labelId));
    if (!da) missing.push({ name: sf.name, criteria: sf.criteria });
  }
  return { labelId, missing };
}

/** Ist dieser Filter einer der Sicherheitsfilter (genau dieses Kriterium)? */
export const isSecurityFilter = (f) => SECURITY_FILTERS.some((sf) => norm(f?.criteria) === norm(sf.criteria));

/**
 * Alle Einstellungen eines Postfachs, die Mails abfließen lassen oder Sicherheitsmails verstecken können: Labels,
 * Filter, Weiterleitungsadressen, automatische Weiterleitung, IMAP, POP, Delegierungen. Nur GET; ein Lese-Scope
 * (gmail.readonly) reicht für alle. Für den Mail-Wächter (S114).
 */
/**
 * Absender-Liste eines Postfachs (Senden-als mit Reply-To) für den Mail-Wächter. EINZIGE Ausnahme zur Versand-Sperre
 * (assertNoSend lehnt den Pfad sonst ab): Board A800 a („Wächter meldet Senden-als und Reply-To“), Entscheidung
 * Orchestrator 24.11.2026 a, nur Lesen. Methode GET und Pfad sind fest verdrahtet, kein Parameter des Aufrufers fließt
 * in die Anfrage außer dem geprüften Postfach; Unterpfade (einzelne Adresse, verify) und jede andere Methode bleiben
 * gesperrt. Liefert nur Adresse und Reply-To, keine Signatur, keinen Anzeigenamen.
 */
export async function readAbsender({ token, mailbox, fetchImpl = fetch }) {
  if (!MAILBOX.test(String(mailbox))) throw new Error(`Gmail-Einrichtung: Postfach ${String(mailbox).slice(0, 60)} ungültig`);
  assertNoSend(mailbox);
  if (!token) throw new Error('Gmail-Einrichtung: kein Zugangstoken');
  let res;
  try {
    res = await fetchImpl(ABSENDER_URL(mailbox), { method: 'GET', headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(30_000) });
  } catch (e) { throw new Error(`Gmail-Einrichtung: ${mailbox} nicht erreichbar (${e?.cause?.code ?? e?.name ?? 'Fehler'})`); }
  const roh = await res.text().catch(() => null);
  if (!res.ok) throw new Error(`Gmail-Einrichtung GET Absender in ${mailbox}: API ${res.status}`);
  let j = null;
  try { j = roh != null && roh.trim() === '' ? {} : JSON.parse(roh); } catch { j = null; }
  if (!j || typeof j !== 'object') throw new Error('Gmail-Einrichtung GET Absender: Antwort unvollständig');
  // Gmail liefert die Primäradresse immer: leer oder keine Liste ist eine kaputte Antwort, kein „keine Absender“
  // (sonst lernte der Wächter den Bereich im nächsten Lauf still neu, reviewer S123 B2)
  const liste = LISTE_AUS(j);
  if (!Array.isArray(liste) || !liste.length || liste.some((x) => typeof x?.sendAsEmail !== 'string' || !x.sendAsEmail.includes('@'))) throw new Error('Gmail-Einrichtung GET Absender: Antwort unvollständig');
  return liste.map((x) => ({ email: x.sendAsEmail.toLowerCase(), replyTo: String(x?.replyToAddress ?? '').trim().toLowerCase() }));
}
// A800 a, nur Lesen (SEND_ALLOW in test/gmail-send-guard.test.mjs): Pfad und Feldname der Gmail-Antwort
const ABSENDER_URL = (mb) => `${USERS}${encodeURIComponent(mb)}/settings/sendAs`;
const LISTE_AUS = (j) => j.sendAs;

export async function readMailSettings({ token, mailbox, fetchImpl = fetch }) {
  const get = (path) => call({ token, mailbox, path, fetchImpl });
  const labels = (await get('labels')).labels ?? [];
  const filters = (await get('settings/filters')).filter ?? [];
  const forwardingAddresses = (await get('settings/forwardingAddresses')).forwardingAddresses ?? [];
  const autoForwarding = await get('settings/autoForwarding');
  const imap = await get('settings/imap');
  const pop = await get('settings/pop');
  const delegates = (await get('settings/delegates')).delegates ?? [];
  const vacation = await get('settings/vacation');
  const absender = await readAbsender({ token, mailbox, fetchImpl });
  return { labels, filters, forwardingAddresses, autoForwarding, imap, pop, delegates, vacation, absender };
}

/**
 * Stand eines Postfachs: Label-ID (oder null) und was fehlt. Nur lesend.
 * @returns {Promise<{ mailbox, labelId: string|null, missing: Array<{ name, criteria? }>, before: { labels: number, filters: object[] } }>}
 */
export async function planSecurityLabel({ labelsToken, filtersToken, mailbox, label, fetchImpl = fetch }) {
  const labels = (await call({ token: labelsToken, mailbox, path: 'labels', fetchImpl })).labels ?? [];
  const filters = (await call({ token: filtersToken, mailbox, path: 'settings/filters', fetchImpl })).filter ?? [];
  const { labelId, missing } = missingSecurityParts({ labels, filters, label, mailbox });
  return { mailbox, labelId, missing, before: { labels: labels.length, filters: filters.map((x) => ({ id: x.id, criteria: x.criteria, action: x.action })) } };
}

/** Legt an, was planSecurityLabel als fehlend meldet. Gibt die angelegten IDs zurück (für den Rückweg von Hand);
 *  onCreated meldet jede Anlage sofort, damit ein Teilfehler keine IDs verliert. */
export async function applySecurityLabel({ labelsToken, filtersToken, mailbox, label, fetchImpl = fetch, onCreated = () => {} }) {
  const plan = await planSecurityLabel({ labelsToken, filtersToken, mailbox, label, fetchImpl });
  const created = [];
  let labelId = plan.labelId;
  if (!labelId) {
    const l = await call({ token: labelsToken, mailbox, path: 'labels', method: 'POST', fetchImpl, body: { name: label, labelListVisibility: 'labelShow', messageListVisibility: 'show' } });
    if (typeof l.id !== 'string') throw new Error('Gmail-Einrichtung: Label ohne ID angelegt');
    labelId = l.id;
    created.push({ name: 'label', id: l.id });
    onCreated(created.at(-1));
  }
  for (const m of plan.missing.filter((x) => x.criteria)) {
    const f = await call({ token: filtersToken, mailbox, path: 'settings/filters', method: 'POST', fetchImpl, body: { criteria: m.criteria, action: { addLabelIds: [labelId] } } });
    created.push({ name: m.name, id: f.id ?? null });
    onCreated(created.at(-1));
  }
  return { mailbox, labelId, created, before: plan.before };
}
