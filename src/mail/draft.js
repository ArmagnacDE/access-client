// Kern von access-mail als Funktion (S112 „Ein Mail-Weg für Sessions und Agenten“): EIN Entwurf in einem Postfach über
// das delegierte Dienstkonto, optional als Antwort in den Verlauf einer Mail. Nutzen: der Befehl access-mail und
// Werkzeuge, die ihren Schlüssel selbst tragen (OpenClaw mail_draft). Kein Senden: einziger Schreibweg ist
// createCheckedDraft (drafts.create). Der Aufrufer konfiguriert den Gmail-Wächter (configureGmailGuard) vorher; die
// Ausgangsmail einer Antwort geht durch ihn (Sicherheitsmails gesperrt).

import { getDelegatedToken } from '../google-auth.js';
import { createCheckedDraft, GMAIL_COMPOSE, GMAIL_READONLY, gmailGet, headerOf, msgIdList } from '../gmail.js';
import { AccessReadError, delegationHint } from '../read/accounts.js';

const ADRESSE = /^[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}$|^[^<>\r\n]*<[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}>$/;
/** An Komma/Semikolon trennen, aber nicht in Anführungszeichen („"Doe, Jane" <j@x>“, Codex S112 #4). */
function splitAddresses(t) {
  const out = []; let cur = ''; let quoted = false;
  for (const ch of t) {
    if (ch === '"') quoted = !quoted;
    if (!quoted && (ch === ',' || ch === ';')) { out.push(cur); cur = ''; } else cur += ch;
  }
  out.push(cur);
  return out;
}
const QUOTES_OK = (a) => (a.match(/"/g) ?? []).length % 2 === 0;
/** Adressliste aus „a@b, c@d“ oder Array; wirft bei Zeilenumbruch oder ungültiger Adresse. */
export function addressList(v, feld) {
  const l = (Array.isArray(v) ? v : splitAddresses(String(v ?? ''))).map((x) => String(x).trim()).filter(Boolean);
  for (const a of l) if (/[\r\n]/.test(a) || !QUOTES_OK(a) || !ADRESSE.test(a)) throw new AccessReadError(`${feld}: „${a.slice(0, 60).replace(/[\r\n]/g, '⏎')}“ ist keine Adresse`, { usage: true });
  return l;
}

async function token(keyFile, mailbox, scope, fetchImpl) {
  try {
    return await getDelegatedToken({ datei: keyFile, sub: mailbox, scopes: [scope], allowedScopes: [scope], fetchImpl });
  } catch (e) {
    if (/nicht lesbar \(ENOENT\)/.test(String(e?.message))) throw new AccessReadError('Schlüssel der Mail-Delegierung fehlt');
    throw delegationHint(e, mailbox);
  }
}

/** Kopfzeilen der Ausgangsmail für eine Antwort (über den Wächter). */
async function replyBase(keyFile, mailbox, id, fetchImpl) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(id))) throw new AccessReadError('replyTo braucht eine Mail-ID (aus der Suche)', { usage: true });
  const m = await gmailGet({
    token: await token(keyFile, mailbox, GMAIL_READONLY, fetchImpl), mailbox, path: `messages/${id}`, fetchImpl,
    params: { format: 'metadata', metadataHeaders: ['From', 'Reply-To', 'Subject', 'Message-ID', 'References'] },
  });
  if (m?.id !== id || typeof m.threadId !== 'string') throw new AccessReadError('Ausgangsmail: Antwort unvollständig');
  const messageId = msgIdList(headerOf(m, 'Message-ID'));
  return {
    an: headerOf(m, 'Reply-To') || headerOf(m, 'From'), betreff: headerOf(m, 'Subject'),
    reply: { inReplyTo: messageId, references: `${msgIdList(headerOf(m, 'References'))} ${messageId}`.trim(), threadId: m.threadId },
  };
}

/**
 * @param {{ keyFile: string, mailbox: string, to?: string|string[]|null, cc?: string|string[], subject?: string|null,
 *   text?: string, html?: string, replyTo?: string|null, attachments?: Array<{ filename, mime, bytes: Buffer }>, fetchImpl?: typeof fetch }} o
 * @returns {Promise<{ postfach, entwurfId, verlauf, an, cc, betreff, anhaenge, link }>}
 */
export async function draftMail({ keyFile, mailbox, to = null, cc = [], subject = null, text, html, replyTo = null, attachments = [], fetchImpl = fetch }) {
  if (!keyFile || !mailbox) throw new Error('draftMail: keyFile und mailbox sind Pflicht');
  if ((typeof text === 'string') === (typeof html === 'string')) throw new AccessReadError('genau eins von text oder html', { usage: true });
  if (!replyTo && (!to || !subject)) throw new AccessReadError('to und subject sind Pflicht (oder replyTo)', { usage: true });
  if (subject != null && /[\r\n]/.test(subject)) throw new AccessReadError('subject: Zeilenumbruch nicht erlaubt', { usage: true });
  let an = to != null ? addressList(to, 'to') : null;
  const kopie = addressList(cc ?? [], 'cc');
  let betreff = subject;
  let reply = null;
  if (replyTo) {
    const b = await replyBase(keyFile, mailbox, replyTo, fetchImpl);
    reply = b.reply;
    if (!an) an = addressList(b.an.replace(/[\r\n]/g, ' '), 'to');
    if (!an.length) throw new AccessReadError('Ausgangsmail ohne Absender; to angeben', { usage: true });
    if (betreff == null) betreff = /^\s*(re|aw|antw)\s*:/i.test(b.betreff) ? b.betreff : `Re: ${b.betreff}`;
  }
  const r = await createCheckedDraft({
    token: await token(keyFile, mailbox, GMAIL_COMPOSE, fetchImpl), expectedMailbox: mailbox, to: an.join(', '), cc: kopie,
    subject: String(betreff).replace(/[\r\n]+/g, ' '), ...(typeof html === 'string' ? { html } : { text }), attachments, reply, fetchImpl,
  });
  return {
    postfach: r.mailbox, entwurfId: r.draftId, verlauf: r.threadId, an, cc: kopie, betreff,
    anhaenge: attachments.map((a) => ({ datei: a.filename, bytes: a.bytes.length })),
    link: `https://mail.google.com/mail/?authuser=${encodeURIComponent(r.mailbox)}#drafts`,
  };
}
