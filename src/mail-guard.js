// Mail-Wächter (S114 „Mail-Wächter: nächtliche Prüfung und 2FA-Filter nachziehen“, Sascha 23.11.2026 „go“). Prüft je
// Postfach, was das delegierte Dienstkonto mail-jobs (Generalschlüssel auf alle Postfächer) anrichten könnte und was
// die Gmail-Filter für Sicherheitsmails übersehen:
//   1. Einstellungen gegen den gesicherten Stand: Filter, Weiterleitungsadressen, automatische Weiterleitung,
//      Delegierungen, IMAP, POP; dazu jede Nacht, ob Sperr-Label und beide Sicherheitsfilter noch da sind;
//   2. Gesendete Mails, deren Client-Fingerabdruck nicht im Grundstand ist (siehe sentFingerprint);
//   3. Mails, die wie 2FA, Codes oder Passwort-Links aussehen, aber das Sperr-Label nicht tragen: entweder trifft ein
//      Merkmal der Liste (src/security-mail.js) und der Filter griff nicht („security-list“), oder ein unbekannter
//      Absender (Kandidat für die Liste, „security“).
//
// NUR LESEND: Gmail nur über gmailGet (Suche und Kopfzeilen, Sperr-Label ausgeschlossen) und readMailSettings (GET).
// Kein Schreiben in Gmail, auch keine Filter (Ergänzung der Liste nur als Vorschlag, eingerichtet mit
// scripts/security-label.mjs nach Freigabe). Ergebnis sind Befunde ohne Mailinhalt: Postfach, Domain, Datum, Betreff
// gekürzt mit maskierten Ziffern. Die Meldung (ntfy) und den Zustand schreibt bin/mail-guard.mjs.
//
// Warum ein Fingerabdruck für „über die API gesendet“: Gmail markiert API-Versand nicht (kein Kopf, kein Label), und
// das Audit-Log der Admin-Konsole ist mit gmail.readonly nicht lesbar. Was bleibt, ist der Aufbau der Mail: Saschas
// Clients (eM Client, Gmail im Browser) erzeugen gleichbleibende Merkmale (User-Agent, Host der Message-ID, Form der
// MIME-Grenze). Eine Mail, die ein Skript über messages.send oder drafts.send verschickt, hat einen anderen Aufbau.
// Grenze: Wer die Merkmale eines bekannten Clients nachbaut, fällt nicht auf; ein Entwurf, den ein Mensch in Gmail
// abschickt, bekommt den Abdruck von Gmail. Unbekannte Abdrücke werden nicht gelernt; annehmen (neuer Client) nur
// ausdrücklich über `mail-guard accept`.

import { createHash } from 'node:crypto';
import { emailOf, gmailGet, gmailGuardConfig, GmailBlockedError, headerOf, listMessageIds } from './gmail.js';
import { isSecurityFilter, missingSecurityParts, readMailSettings } from './gmail-setup.js';
import { isSecurityMail, SENDER_QUERY, SUBJECT_QUERY } from './security-mail.js';

const TAG = 86_400_000;
const STUNDE = 3_600_000;
const UEBERLAPPUNG_MS = 2 * STUNDE; // je Lauf etwas zurück, doppelte Meldungen verhindert `reported`
const REPORTED_MAX = 5000;

const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);
/** JSON mit sortierten Schlüsseln und sortierten Text-Listen (Label-IDs): gleicher Inhalt → gleicher Hash. */
const kanonisch = (v) => (Array.isArray(v) ? (v.every((x) => typeof x === 'string') ? [...v].sort() : v.map(kanonisch))
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, kanonisch(v[k])])) : v);
const stabil = (v) => JSON.stringify(kanonisch(v));
const hdr = (headers, name) => (headers ?? []).find((h) => String(h?.name).toLowerCase() === name.toLowerCase())?.value ?? '';

/**
 * Betreff für Meldungen: eine Zeile, höchstens 32 Zeichen. Adressen auf die Domain gekürzt (auch "lokal"@domain), Codes
 * maskiert: Ziffernfolgen ab 3 (auch „123 456“, „123-456“) und gemischte Folgen aus Buchstaben und Ziffern ab 3 („A7K“),
 * außer „2FA“/„MFA“ (Codex S114 #5, reviewer S114 nice 3).
 */
export function maskSubject(s, max = 32) {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim()
    .replace(/(?:"[^"]*"|[^\s<>"@]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g, (_, d) => `•@${d}`)
    .replace(/\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{3,}\b/g, (w) => (/^[0-9]?[a-z]fa$/i.test(w) ? w : '•••'))
    .replace(/\d{3,}(?:[ -]\d{3,})*/g, '••••');
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

const ZWEITE_EBENE = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']);
/** Domain einer Adresse („Name <a@login.x.de>“ → „x.de“), ohne Subdomains; nie die volle Adresse. */
export function domainOf(value) {
  const d = emailOf(value).split('@')[1]?.replace(/[^a-z0-9.-]/g, '') ?? '';
  const t = d.split('.').filter(Boolean);
  if (t.length < 2) return d || '?';
  const n = t.length > 2 && ZWEITE_EBENE.has(t.at(-2)) && t.at(-1).length === 2 ? 3 : 2;
  return t.slice(-n).join('.');
}

/**
 * Fingerabdruck einer gesendeten Mail aus Kopfzeilen (Array {name, value}): Client ohne Version (User-Agent oder
 * X-Mailer), Host der Message-ID, Form der MIME-Grenze (Hex-Folgen als #; „-“ = einteilig).
 */
export function sentFingerprint(headers) {
  // nur begrenzte, normalisierte Merkmale, keine freien Kopftexte (Codex S114 #5): Client-Name ohne Version und ohne
  // Adressen, vom Host der Message-ID nur die Domain (letzte zwei Teile), Ziffern und Hex-Folgen als #
  const ua = (hdr(headers, 'User-Agent') || hdr(headers, 'X-Mailer')).replace(/\S*@\S*/g, '').replace(/\s*\(.*$/, '')
    .replace(/[/ ]?v?\d[\w.]*/g, '').replace(/[^A-Za-z0-9 ._-]/g, '').trim().slice(0, 30) || '-';
  const roh = (/@([^>\s]+)>?\s*$/.exec(hdr(headers, 'Message-ID'))?.[1] ?? '').toLowerCase().replace(/[^a-z0-9.-]/g, '');
  const host = roh ? roh.split('.').filter(Boolean).slice(-2).join('.').replace(/[0-9a-f]{8,}/g, '#').replace(/\d+/g, '#') : '-';
  const grenze = /boundary="?([^";]+)"?/i.exec(hdr(headers, 'Content-Type'))?.[1];
  // Zufallsteile: alphanumerische Folgen ab 6 (Base62, reviewer S114 nice 4) und Hex-Folgen als #
  const form = grenze ? grenze.replace(/[A-Za-z0-9]{6,}/g, '#').replace(/[0-9A-Fa-f]+/g, '#').replace(/#+/g, '#').replace(/[^A-Za-z#=_.+-]/g, '').slice(0, 24) : '-';
  return `ua:${ua} id@${host} b:${form}`;
}

// Merkmale von 2FA-, Code- und Passwort-Mails, weiter gefasst als die Filterliste: Sie sollen Kandidaten finden, nicht
// sperren. Wortgrenzen nur an ASCII-Stellen (\b kennt keine Umlaute).
const KANDIDATEN = Object.freeze([
  { name: 'code-wort', re: /(zugangs|bestätigungs|sicherheits|verifizierungs|anmelde|einmal|login|access|security|verification|authentication|auth|confirmation|sign-?in|zugriffs)[- ]?code/iu },
  // Rabatt- und Gutscheincodes zählen nicht (statt Jahreszahlen auszunehmen: „Your code: 2026“ ist ein Code, Codex-Folgerunde)
  { name: 'code-ziffern', re: /(^|\D)\d{4,8}(\D|$).*(?<![-/\w])code\b|(?<![-/\w])code\b.*(^|\D)\d{4,8}(\D|$)/iu, ausser: /\b(discount|promo|coupon|voucher|sale)\b|rabatt|gutschein|angebot/iu },
  { name: 'kurzwort', re: /\b(otp|tan|pin|passcode|2fa|mfa)\b.*(login|log in|anmeld|sign|konto|account|code|zugang|access|karte|card|\d{4,})|(login|log in|anmeld|sign|konto|account|zugang|access|karte|card).*\b(otp|tan|pin|passcode|2fa|mfa)\b|\b(otp|passcode|2fa|mfa)\b/iu },
  { name: 'zwei-faktor', re: /(two[- ]factor|zwei[- ]faktor|2-step|two-step|zweistufig|multi-factor|(authentication|authentifizierungs?)[- ](code|method|methode|app|verfahren))/iu },
  { name: 'passwort', re: /(passwor[dt]|kennwort)\b.*(reset|zurücksetzen|ändern|change|vergessen|forgot|neu)|(reset|forgot|vergessen|neues)\s+(your\s+|dein\s+|ihr\s+)?(passwor|kennwort)/iu },
  { name: 'bestaetigen', re: /\b(confirm|verify|bestätige|bestätigen|verifiziere|verifizieren)\b.*(e-?mail|konto|account|anmeldung|login|sign[- ]?in|identit)/iu },
  { name: 'neue-anmeldung', re: /\b(neue[rs]?|new)\s+(anmeldung|sign[- ]?in|login|gerät|device)/iu },
  { name: 'sicherheitswarnung', re: /(security alert|sicherheitswarnung|sicherheitshinweis|unusual (sign|activity|login)|ungewöhnliche)/iu },
  { name: 'anmelde-link', re: /(sign[- ]?in|log[- ]?in|anmelde|magic)[- ]?link/iu },
]);

/** Sieht die Mail wie 2FA/Code/Passwort-Link aus? → { pattern } oder null. Nur Betreff (From wird nicht gewertet). */
export function securityCandidate({ subject }) {
  const s = String(subject ?? '');
  const k = KANDIDATEN.find((x) => x.re.test(s) && !x.ausser?.test(s));
  return k ? { pattern: k.name } : null;
}

// Grobe Gmail-Suche für Kandidaten (Gmail sucht ganze Wörter, deshalb auch die Komposita); fein sortiert
// securityCandidate. Keine Klammern oder Anführungszeichen in Begriffen (assertBalancedQuery).
const SUCHWOERTER = ['code', 'codes', 'verification', 'verify', 'verifizieren', 'verifizierung', 'bestätigen', 'bestätige', 'confirm',
  'passwort', 'password', 'kennwort', '"sign in"', '"sign-in"', 'login', '"log in"', 'anmeldung', 'anmelden', 'anmeldelink', 'otp', 'pin',
  'tan', 'passcode', 'authentication', 'authentifizierung', '2fa', 'mfa', '"two-factor"', '"security alert"', 'sicherheitswarnung',
  'sicherheitshinweis', 'zugangscode', 'sicherheitscode', 'bestätigungscode', 'verifizierungscode', 'einmalcode', 'anmeldecode',
  'zugriffscode', '"neues gerät"', '"new device"', 'unusual', 'link'];
// Vereinigung mit den Merkmalen der Liste (Betreffe UND Absender, Codex S114 #6): sonst fände der Wächter Listen-Treffer
// ohne Label nicht, deren Betreff kein Suchwort enthält. BEWUSST NICHT: Spam und Papierkorb (Codex #6 schlug in:anywhere
// vor). Gmail-Filter wirken dort nicht, Phishing mit Sicherheits-Betreffen läge jede Nacht als „Filter griff nicht“ in der
// Meldung (reviewer S114 B1); Agenten sehen Spam nur mit ausdrücklichem in:spam, dort greift die Merkmal-Sperre.
export const CANDIDATE_QUERY = `(subject:(${SUCHWOERTER.join(' OR ')}) OR ${SUBJECT_QUERY} OR from:(${SENDER_QUERY})) -in:sent -in:drafts -in:chats`;

const ACTION_LABEL = { TRASH: 'löschen', SPAM: 'als Spam', IMPORTANT: 'wichtig', STARRED: 'Stern' };
function filterSummary(f, labelNames) {
  const krit = Object.keys(f?.criteria ?? {}).filter((k) => f.criteria[k] !== false && f.criteria[k] !== '' && f.criteria[k] != null);
  const a = f?.action ?? {};
  const tun = [];
  if (a.forward) tun.push(`Weiterleitung an @${domainOf(a.forward)}`);
  for (const l of a.addLabelIds ?? []) tun.push(ACTION_LABEL[l] ?? (labelNames.get(l) === 'sperr' ? 'Sperr-Label' : 'Label'));
  for (const l of a.removeLabelIds ?? []) tun.push(l === 'INBOX' ? 'Posteingang überspringen' : l === 'UNREAD' ? 'als gelesen' : l === 'SPAM' ? 'nie Spam' : 'Label entfernen');
  return `${isSecurityFilter(f) ? 'Sicherheitsfilter' : 'Filter'} (Kriterien ${krit.join(',') || '–'}; ${tun.join(', ') || 'keine Aktion'})`;
}

/**
 * Vergleichbare Einträge aus den Einstellungen (readMailSettings): Schlüssel = Hash des Inhalts, Wert = Kurztext ohne
 * volle Adressen. Der Zustand speichert nur diese, keine Filterkriterien im Klartext.
 */
export function settingsItems(snap, { label = gmailGuardConfig()?.blockedLabel } = {}) {
  const out = {};
  const put = (key, summary, domain = null) => { out[key] = { summary, ...(domain ? { domain } : {}) }; };
  // Schlüssel-Format 2 (S123): Weiterleitungsadressen nur nach Adresse. Ein Zustand ohne diese Marke (v1.4.0) lernt die
  // Weiterleitungsadressen einmal still neu, statt jede bekannte Adresse als neu zu melden (Codex S123 Folgerunde).
  put('format:2', 'Schlüssel-Format 2');
  const labelNames = new Map((snap.labels ?? []).map((l) => [l.id, String(l.name ?? '').toLowerCase().replace(/\s+/g, '-') === label ? 'sperr' : 'andere']));
  for (const f of snap.filters ?? []) {
    put(`filter:${sha(stabil([f?.criteria ?? {}, f?.action ?? {}]))}`, filterSummary(f, labelNames), f?.action?.forward ? domainOf(f.action.forward) : null);
  }
  for (const w of snap.forwardingAddresses ?? []) {
    const d = domainOf(w?.forwardingEmail);
    // Schlüssel nur die Adresse (S123, Board A793 a): ein Statuswechsel einer bekannten Adresse ist kein Befund
    put(`forward:${sha(String(w?.forwardingEmail).toLowerCase())}`, `Weiterleitungsadresse @${d} (${w?.verificationStatus ?? '?'})`, d);
  }
  const af = snap.autoForwarding ?? {};
  if (af.enabled) {
    const d = domainOf(af.emailAddress);
    put(`autoForwarding:${sha(`${String(af.emailAddress).toLowerCase()}|${af.disposition}`)}`, `Automatische Weiterleitung an @${d} (${af.disposition ?? '?'})`, d);
  } else put('autoForwarding:aus', 'Automatische Weiterleitung aus');
  // alle Felder, auch Löschverhalten (Codex S114 #7: expungeBehavior, autoExpunge, maxFolderSize, POP disposition)
  const felder = (o, ohne) => Object.entries(kanonisch(o ?? {})).filter(([k]) => k !== ohne).map(([k, v]) => `${k} ${v}`).join(', ');
  const imap = snap.imap ?? {};
  put(`imap:${sha(stabil(imap))}`, `IMAP ${imap.enabled ? 'an' : 'aus'}${felder(imap, 'enabled') ? ` (${felder(imap, 'enabled')})` : ''}`);
  const pop = snap.pop ?? {};
  put(`pop:${sha(stabil(pop))}`, `POP ${pop.accessWindow ?? '?'}${felder(pop, 'accessWindow') ? ` (${felder(pop, 'accessWindow')})` : ''}`);
  // Abwesenheitsnotiz (A800 a): Schlüssel = Hash über Betreff, Text und Einschränkungen; gespeichert wird nur ein Kurztext
  // ohne Inhalt (Betreff maskiert). Geändert = neuer Schlüssel = Alarm; aus = still.
  const v = snap.vacation;
  if (v && typeof v === 'object') {
    if (v.enableAutoReply) {
      const fuer = v.restrictToContacts ? 'nur Kontakte' : v.restrictToDomain ? 'nur Domain' : 'an alle';
      put(`vacation:${sha(stabil(v))}`, `Abwesenheitsnotiz an (${fuer}, Betreff „${maskSubject(v.responseSubject, 24).replace(/[^\p{L} .:,!?-]/gu, '•')}“)`);
    } else put('vacation:aus', 'Abwesenheitsnotiz aus');
  }
  // Senden-als mit Reply-To (A800 a): neue Adresse oder neue/geänderte Antwortadresse = Alarm; entfernt = still
  for (const x of snap.absender ?? []) {
    put(`absender:${sha(`${x.email}|${x.replyTo}`)}`, `Senden als @${domainOf(x.email)}${x.replyTo ? ` (Reply-To @${domainOf(x.replyTo)})` : ''}`, domainOf(x.replyTo || x.email));
  }
  for (const x of snap.delegates ?? []) {
    const d = domainOf(x?.delegateEmail);
    put(`delegate:${sha(`${String(x?.delegateEmail).toLowerCase()}|${x?.verificationStatus}`)}`, `Delegierung an @${d} (${x?.verificationStatus ?? '?'})`, d);
  }
  return out;
}

// Weiterleitungen melden nur, was Mails nach außen bringen kann (S123, Board A789 b, A793 a: mail@ hat Lexware
// „accepted“ und invoicefetcher „pending“, automatische Weiterleitung aus): eine neue Adresse und eine eingeschaltete
// oder umgestellte automatische Weiterleitung. Still bleiben Entfernen, Ausschalten und Statuswechsel einer bekannten
// Adresse; eine bestätigte Adresse leitet erst mit Weiterleitung oder Filter weiter, und beide melden sich selbst.
// Abwesenheitsnotiz, Senden-als und Reply-To ebenso: Alarm nur bei neu oder geändert (A800 a).
const STILL_ENTFERNT = /^(forward|autoForwarding|vacation|absender):/;
const STILL_NEU = new Set(['autoForwarding:aus', 'vacation:aus', 'format:2']);
// Bereiche, die ein älterer Zustand noch nicht kennt, werden einmal still gelernt (Update von v1.4.0 ohne Fehlalarm)
const NEUE_BEREICHE = ['vacation:', 'absender:'];
/** Unterschiede zweier settingsItems: neu, entfernt (eine Änderung erscheint als beides), ohne die stillen Fälle. */
export function diffSettings(alt, neu) {
  const out = [];
  const altKeys = Object.keys(alt ?? {});
  const unbekannt = NEUE_BEREICHE.filter((b) => !altKeys.some((k) => k.startsWith(b)));
  if (!altKeys.includes('format:2')) unbekannt.push('forward:');
  for (const [key, v] of Object.entries(neu ?? {})) {
    if (key in (alt ?? {}) || STILL_NEU.has(key) || unbekannt.some((b) => key.startsWith(b))) continue;
    out.push({ change: 'neu', key, ...v });
  }
  for (const [key, v] of Object.entries(alt ?? {})) if (!(key in (neu ?? {})) && !STILL_ENTFERNT.test(key)) out.push({ change: 'entfernt', key, ...v });
  return out;
}

const sek = (ms) => Math.floor(ms / 1000);
/**
 * Alle IDs einer Suche im Zeitraum [from, to), in Zeitscheiben (ein Tag, bei voller Scheibe halbiert bis eine Stunde),
 * damit ein Rückstand aufholt statt immer dieselben neuesten maxMessages zu holen (reviewer S114 B2, Codex #1).
 * truncated: eine Stundenscheibe war voller als max; deren Rest bleibt ungeprüft und wird als Befund gemeldet.
 */
async function listWindow({ token, mailbox, q, from, to, max, fetchImpl }) {
  const ids = new Map();
  let truncated = false;
  for (let start = from; start < to;) {
    let len = Math.min(TAG, to - start);
    for (;;) {
      // eine Sekunde Überlappung an der Scheibengrenze (Gmail-Grenzen sekundengenau), doppelte IDs fallen in der Map weg
      const r = await listMessageIds({ token, mailbox, q: `${q} after:${sek(start) - 1} before:${sek(start + len)}`, max, fetchImpl });
      if (!r.truncated || len <= STUNDE) {
        for (const x of r.ids) ids.set(x.id, x);
        if (r.truncated) truncated = true;
        break;
      }
      len = Math.max(STUNDE, Math.floor(len / 2));
    }
    start += len;
  }
  return { ids: [...ids.values()], truncated };
}
const SPAM_TRASH = new Set(['SPAM', 'TRASH']);
const adressDomains = (v) => [...String(v ?? '').matchAll(/[^\s<>",;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)].map((m) => domainOf(m[0]));

const datum = (ms) => (Number.isFinite(ms) ? new Intl.DateTimeFormat('de-DE', { timeZone: 'Europe/Berlin', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(ms)).replace(',', '') : '?');
const SENT_HEADERS = Object.freeze(['Message-ID', 'User-Agent', 'X-Mailer', 'Content-Type', 'To', 'Subject']);
const MAIL_HEADERS = Object.freeze(['From', 'Subject']);

async function kopf({ token, mailbox, id, headers, fetchImpl }) {
  try {
    const m = await gmailGet({ token, mailbox, path: `messages/${encodeURIComponent(id)}`, params: { format: 'metadata', metadataHeaders: headers }, fetchImpl });
    // Nur, was gebraucht wird: kein Auszug (snippet), keine Größe
    return { id: m.id, at: Number(m.internalDate), labelIds: m.labelIds ?? [], headers: (m.payload?.headers ?? []).filter((h) => headers.some((n) => n.toLowerCase() === String(h?.name).toLowerCase())) };
  } catch (e) {
    if (e instanceof GmailBlockedError) return null; // trägt inzwischen das Sperr-Label: genau richtig, nicht melden
    throw e;
  }
}

/**
 * Ein Postfach prüfen. state = Zustand des letzten Laufs (oder null: Grundstand anlegen, Einstellungen und die
 * Abdrücke der Gesendeten der letzten learnDays Tage werden gelernt, nicht gemeldet). Wirft, wenn das Postfach nicht
 * lesbar ist (dann kein neuer Zustand). Gibt Befunde und den neuen Zustand zurück; speichern tut der Aufrufer.
 */
export async function scanMailbox({ token, mailbox, state, now = Date.now(), days = 2, learnDays = 60, maxMessages = 1000, fetchImpl = fetch }) {
  const label = gmailGuardConfig()?.blockedLabel;
  if (!label) throw new Error('Mail-Wächter: Gmail-Wächter nicht konfiguriert (configureGmailGuard)');
  const baseline = !state;
  const findings = [];
  const reported = new Set(state?.reported ?? []);

  const snap = await readMailSettings({ token, mailbox, fetchImpl });
  const { missing } = missingSecurityParts({ labels: snap.labels, filters: snap.filters, label, mailbox });
  if (missing.length) findings.push({ kind: 'setup', detail: `fehlt ${missing.map((m) => m.name).join(', ')}` });
  const items = settingsItems(snap, { label });
  // Einstellungs-Diff vor der Label-Prüfung: ein gelöschtes Sperr-Label tarnt keinen neuen Weiterleitungsfilter
  // (reviewer S114 nice 1); er braucht keinen Mailabruf
  if (!baseline) for (const d of diffSettings(state.settings, items)) findings.push({ kind: 'settings', change: d.change, summary: d.summary, ...(d.domain ? { domain: d.domain } : {}) });
  // Ohne Sperr-Label liest kein Inhaltspfad (requireLabel): Befund melden, Stand nicht anfassen (Codex S114 #4)
  if (missing.some((m) => m.name === 'label')) {
    return { mailbox, baseline, findings, incomplete: true, truncated: false, counts: { filters: snap.filters.length, findings: findings.length }, state: state ?? null };
  }

  // Ganzer Rückstand seit dem letzten gespeicherten Lauf, nicht gekappt (Codex S114 #2): ein Meldungsausfall verliert nichts
  const von = baseline ? now - days * TAG : Number(state.lastRun) - UEBERLAPPUNG_MS;
  let spam = 0;

  // 2. Gesendete. Grundstand: die neuesten maxMessages der letzten learnDays Tage lernen. BEWUSST NICHT UMGESETZT:
  // ein gekürzter Grundstand lernt nur die neuesten; Folge sind höchstens Fehlalarme, kein Verlust.
  const known = baseline ? {} : { ...(state.sent?.known ?? {}) };
  const gesendet = baseline
    ? await listMessageIds({ token, mailbox, q: `in:sent after:${sek(now - learnDays * TAG)}`, max: maxMessages, fetchImpl })
    : await listWindow({ token, mailbox, q: 'in:sent', from: von, to: now, max: maxMessages, fetchImpl });
  let sentChecked = 0;
  for (const { id } of gesendet.ids) {
    if (!baseline && reported.has(id)) continue;
    const m = await kopf({ token, mailbox, id, headers: SENT_HEADERS, fetchImpl });
    if (!m) continue;
    sentChecked++;
    const fp = sentFingerprint(m.headers);
    if (baseline) { known[fp] = { count: (known[fp]?.count ?? 0) + 1, last: Math.max(known[fp]?.last ?? 0, m.at) }; continue; }
    reported.add(id);
    if (known[fp]) { known[fp] = { ...known[fp], count: (known[fp].count ?? 0) + 1, last: Math.max(known[fp].last ?? 0, m.at) }; continue; }
    const to = adressDomains(hdr(m.headers, 'To'));
    findings.push({ kind: 'sent', id, date: datum(m.at), domain: `${to[0] ?? '?'}${to.length > 1 ? ` +${to.length - 1}` : ''}`, subject: maskSubject(hdr(m.headers, 'Subject')), detail: fp });
  }

  // 3. Sicherheitsmails ohne Sperr-Label (gmailGet schließt das Label in der Suche aus)
  const kandidaten = await listWindow({ token, mailbox, q: CANDIDATE_QUERY, from: von, to: now, max: maxMessages, fetchImpl });
  let securityChecked = 0;
  for (const { id } of kandidaten.ids) {
    if (reported.has(id)) continue;
    const m = await kopf({ token, mailbox, id, headers: MAIL_HEADERS, fetchImpl });
    if (!m) continue;
    if (m.labelIds.some((l) => SPAM_TRASH.has(l))) { spam++; continue; }
    securityChecked++;
    const s = { from: hdr(m.headers, 'From'), subject: hdr(m.headers, 'Subject') };
    const liste = isSecurityMail(s);
    const k = liste ? null : securityCandidate(s);
    if (!liste && !k) continue;
    reported.add(id);
    findings.push({ kind: liste ? 'security-list' : 'security', id, date: datum(m.at), domain: domainOf(s.from), subject: maskSubject(s.subject), ...(k ? { detail: k.pattern } : {}) });
  }

  // Volle Stundenscheibe: deren Rest bleibt ungeprüft. BEWUSST: laut melden und weiter vorrücken statt jede Nacht an
  // derselben Stelle zu hängen (mehr als maxMessages Treffer in einer Stunde heißt Mail-Bombing, das gehört sofort
  // angesehen). Ein gekürzter Grundstand bei den Gesendeten ist kein Befund (s. o.).
  const truncated = (!baseline && gesendet.truncated) || kandidaten.truncated;
  if (truncated) findings.push({ kind: 'error', detail: `zu viele Treffer (über ${maxMessages} in einer Stunde), Rest dieser Stunde nicht geprüft` });
  return {
    mailbox, baseline, findings, truncated, incomplete: truncated,
    counts: { filters: snap.filters.length, settings: Object.keys(items).length, sentChecked, fingerprints: Object.keys(known).length, securityChecked, spam, findings: findings.length, ...(baseline && gesendet.truncated ? { lernenGekuerzt: true } : {}) },
    state: { version: 1, mailbox, lastRun: now, settings: items, sent: { known }, reported: [...reported].slice(-REPORTED_MAX) },
  };
}

const LAUT = new Set(['sent', 'settings', 'setup', 'security-list', 'error']);
// Rangfolge in der Meldung (reviewer S114 B3): Einstellungen, Einrichtung und Ausfälle zuerst und nie gekürzt
const RANG = { settings: 0, setup: 0, error: 0, sent: 1, 'security-list': 2, security: 3 };
const kurz = (mb) => `${String(mb).split('@')[0]}@`;
function zeile(mb, f) {
  switch (f.kind) {
    case 'sent': return `${kurz(mb)}: gesendet von unbekanntem Client ${f.date} an @${f.domain} „${f.subject}“ [${f.detail}]`;
    case 'security': return `${kurz(mb)}: 2FA ohne Label ${f.date} von @${f.domain} „${f.subject}“`;
    case 'security-list': return `${kurz(mb)}: Sicherheitsmail ohne Label (Filter griff nicht) ${f.date} von @${f.domain} „${f.subject}“`;
    case 'settings': return `${kurz(mb)}: ${f.change} ${f.summary}`;
    case 'setup': return `${kurz(mb)}: Sperr-Label/Sicherheitsfilter ${f.detail}`;
    case 'error': return `${kurz(mb)}: nicht geprüft (${f.detail})`;
    default: return `${kurz(mb)}: ${f.kind}`;
  }
}

/** ntfy-Meldung aus den Ergebnissen aller Postfächer, oder null ohne Befund. Höchstens 15 Zeilen, Lautes zuerst;
 *  `lines` trägt alle Zeilen fürs Log (Codex S114 #3). */
export function formatNotification(results, { maxLines = 15 } = {}) {
  const alle = results.flatMap((r) => r.findings.map((f) => ({ mb: r.mailbox, f })));
  if (!alle.length) return null;
  alle.sort((a, b) => (RANG[a.f.kind] ?? 9) - (RANG[b.f.kind] ?? 9));
  const zeilen = alle.map(({ mb, f }) => zeile(mb, f));
  const fest = alle.filter(({ f }) => RANG[f.kind] === 0).length;
  const rest = Math.max(0, maxLines - fest);
  const weg = zeilen.length - fest - Math.min(rest, zeilen.length - fest);
  const body = zeilen.slice(0, fest + Math.min(rest, zeilen.length - fest)).join('\n') + (weg > 0 ? `\n+${weg} weitere (Log des Jobs)` : '');
  return { title: `Mail-Wächter: ${alle.length} Befund${alle.length === 1 ? '' : 'e'}`, body, lines: zeilen, priority: alle.some(({ f }) => LAUT.has(f.kind)) ? '4' : '3' };
}

/** Vorschlag für die Merkmal-Liste aus Kandidaten: je Absender-Domain Anzahl, Muster, Beispiel-Betreffe (maskiert). */
export function proposeFromFindings(results) {
  const m = new Map();
  for (const r of results) for (const f of r.findings) {
    if (f.kind !== 'security' && f.kind !== 'security-list') continue;
    const k = `${f.kind}|${f.domain}`;
    const e = m.get(k) ?? { kind: f.kind, domain: f.domain, count: 0, patterns: new Set(), subjects: new Set(), mailboxes: new Set() };
    e.count++; if (f.detail) e.patterns.add(f.detail); if (e.subjects.size < 3) e.subjects.add(f.subject); e.mailboxes.add(kurz(r.mailbox));
    m.set(k, e);
  }
  return [...m.values()].sort((a, b) => b.count - a.count)
    .map((e) => ({ kind: e.kind, domain: e.domain, count: e.count, patterns: [...e.patterns], subjects: [...e.subjects], mailboxes: [...e.mailboxes] }));
}
