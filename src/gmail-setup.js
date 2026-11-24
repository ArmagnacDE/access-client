// Sperr-Label für Sicherheitsmails in einem Postfach einrichten (S112 „Ein Mail-Weg für Sessions und Agenten“, Sascha
// 23.11.2026, Board A694 a). Label (z. B. security-no-read) und die zwei Gmail-Filter aus Unraid openclaw/README.md
// „Gmail-Filter für Sicherheitsmails“; der Gmail-Wächter (src/gmail.js, requireLabel) liest ein Postfach erst, wenn
// das Label dort existiert.
//
// Grenzen: nur GET labels / settings/filters und POST labels / settings/filters (Anlegen). Kein Ändern, kein Löschen,
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
const MAILBOX = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;

async function call({ token, mailbox, path, method = 'GET', body, fetchImpl }) {
  if (!MAILBOX.test(String(mailbox))) throw new Error(`Gmail-Einrichtung: Postfach ${String(mailbox).slice(0, 60)} ungültig`);
  assertNoSend(path); assertNoSend(mailbox);
  if (!PFADE.has(path) || !['GET', 'POST'].includes(method)) throw new Error(`Gmail-Einrichtung: ${method} ${path} nicht erlaubt`);
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
  if (res.ok && method === 'GET' && path === 'settings/filters' && roh != null && roh.trim() === '') j = {};
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

/**
 * Stand eines Postfachs: Label-ID (oder null) und was fehlt. Nur lesend.
 * @returns {Promise<{ mailbox, labelId: string|null, missing: Array<{ name, criteria? }>, before: { labels: number, filters: object[] } }>}
 */
export async function planSecurityLabel({ labelsToken, filtersToken, mailbox, label, fetchImpl = fetch }) {
  const key = labelKey(label);
  const labels = (await call({ token: labelsToken, mailbox, path: 'labels', fetchImpl })).labels ?? [];
  const treffer = labels.filter((l) => labelKey(l?.name) === key);
  if (treffer.length > 1) throw new Error(`Gmail-Einrichtung: ${mailbox} hat ${treffer.length} Labels namens ${label}; bitte von Hand bereinigen`);
  const labelId = treffer[0]?.id ?? null;
  const filters = (await call({ token: filtersToken, mailbox, path: 'settings/filters', fetchImpl })).filter ?? [];
  const missing = [];
  if (!labelId) missing.push({ name: 'label' });
  for (const sf of SECURITY_FILTERS) {
    const da = labelId && filters.some((x) => norm(x?.criteria) === norm(sf.criteria) && (x?.action?.addLabelIds ?? []).includes(labelId));
    if (!da) missing.push({ name: sf.name, criteria: sf.criteria });
  }
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
