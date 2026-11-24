// Merkmale von Sicherheitsmails (Passwort-Reset, Login-Codes, 2FA): EINE Liste für die Gmail-Filter der Einrichtung
// (src/gmail-setup.js), den Gmail-Wächter (src/gmail.js, blockSecurityContent) und den Mail-Wächter (src/mail-guard.js,
// der Mails mit Merkmal, aber ohne Sperr-Label meldet und Kandidaten für diese Liste vorschlägt). Ursprung: Unraid
// openclaw/README.md „Gmail-Filter für Sicherheitsmails“ (S29, Board E963 a); seit S137 ist diese Datei die einzige
// Quelle, das README verweist hierher.
// Warum auch im Wächter: Gmail-Filter wirken nur auf neue Mails, ältere Sicherheitsmails tragen das Label nicht
// (S112 „Ein Mail-Weg für Sessions und Agenten“, 24.11.2026).
//
// BEWUSST NICHT UMGESETZT (Cross-Review S112, Codex #1): Die Liste deckt nicht jede Sicherheitsmail ab (z. B. Betreff
// „Your authentication code“ von einem anderen Absender). Sie ist absichtlich genau die der Gmail-Filter (eine Quelle,
// Filter stehen seit 24.11. in allen Postfächern); erweitert wird sie mit Sascha, dann Filter neu (security-label.mjs).
// Lücken findet seit S114 der Mail-Wächter (src/mail-guard.js, `mail-guard propose`).

export const SECURITY_SUBJECTS = Object.freeze(['password reset', 'reset your password', 'Passwort zurücksetzen', 'Passwort vergessen',
  'verification code', 'Bestätigungscode', 'Verifizierungscode', 'security code', 'Sicherheitscode', 'login code', 'Anmeldecode',
  'sign-in code', 'one-time code', 'one-time password', 'Einmalcode', 'Einmalpasswort', '2FA', 'two-factor', 'Zwei-Faktor',
  'magic link', 'Anmeldelink', 'login link', 'new sign-in',
  // Ergänzung S114 (Mail-Wächter, Board A782 a), Belege aus dem propose-Lauf 24.11.2026 über 90 Tage
  'verify your email', 'neues Passwort', 'new login', 'new device', 'multi-factor', 'two-step authentication', 'Verifizieren Sie Ihre Identität',
  'security alert', 'Sicherheitswarnung',
  'your code is', 'Dein Code lautet', 'Ihr Code lautet',
  // Ergänzung S123 (Mail-Weg Nacharbeiten): dieselben Arten aus A782 a in Varianten und auf Französisch
  'verify email', 'confirm your email', 'E-Mail-Adresse bestätigen', 'bestätige deine E-Mail', 'bestätigen Sie Ihre E-Mail',
  'vérifiez votre adresse e-mail', 'confirmez votre adresse e-mail',
  'new password', 'nouveau mot de passe', 'réinitialiser votre mot de passe', 'mot de passe oublié',
  // nur mit Anmelde-Bezug (Codex S123 #1): „neues Gerät“, „nouvel appareil“ allein träfen Liefer- und Versandmails
  // „neue Anmeldung bei“, „nouvelle connexion“ allein: Veranstaltungen, Zugverbindungen (Codex S123 Folgerunde)
  'neues Gerät angemeldet', 'nouvelle connexion à votre compte', 'connexion depuis un nouvel appareil',
  // nie „zweistufige“, „deux facteurs“, „2-step“, „two-step“ allein: „zweistufige Destillation“, „les deux facteurs d’un
  // grand Armagnac“, „2 step payment plan“ (reviewer S123), „Two-step distillation“ (S137, Fehltreffer aus v1.4.0)
  '2-step verification', 'Multi-Faktor', 'zweistufige Verifizierung', 'à deux facteurs', 'multifacteur',
  'verify your identity', 'Identität verifizieren', 'Identität bestätigen', 'vérifiez votre identité',
  // BEWUSST NICHT: „Sicherheitshinweis“ (allein träfe Produktsicherheit/GPSR); A782 f deckt „Sicherheitswarnung“/
  // „security alert“/„alerte de sécurité“
  'alerte de sécurité', 'code de vérification',
  // Ergänzung S137 (reviewer: Dropbox, Microsoft, Amazon, Atlassian, Bitwarden schreiben so); passt erst, seit der
  // Betreff-Filter auf mehrere Filter verteilt wird. Neue Phrasen immer ans Ende: dann ändert sich nur der letzte Filter.
  'two-step verification', 'two-step login', 'zweistufige Authentifizierung', 'vérifier votre identité']);
/** Nur Absender, die ausschließlich Sicherheitsmails schicken (GitHub, Shopify u. ä. fängt der Betreff). */
export const SECURITY_SENDERS = Object.freeze(['accounts.google.com', 'account-security-noreply@accountprotection.microsoft.com',
  'appleid@id.apple.com', 'security@facebookmail.com']);

/** Ganze Betreff-Suche (für Suchen der API und den Wächter; dort gilt die Filter-Längengrenze nicht). */
export const SUBJECT_QUERY = `subject:(${SECURITY_SUBJECTS.map((s) => `"${s}"`).join(' OR ')})`;
/** Längengrenze je Gmail-Filter, mit Abstand zur Grenze von Gmail (S137). */
export const FILTER_QUERY_MAX = 1400;
/**
 * Dieselbe Liste auf mehrere Gmail-Filter verteilt, je unter FILTER_QUERY_MAX Zeichen (S137, reviewer: ein Filter hatte
 * nur noch 8 Zeichen Luft und zwang zum Weglassen echter Merkmale). Gierig in Listenreihenfolge, also stabil: eine
 * neue Phrase am Ende ändert nur den letzten Filter. Phrasen immer in Anführungszeichen (Rundlauf mit Gmail erprobt).
 */
export const SUBJECT_QUERIES = Object.freeze((() => {
  const out = [];
  let teil = [];
  const q = (t) => `subject:(${t.map((s) => `"${s}"`).join(' OR ')})`;
  for (const s of SECURITY_SUBJECTS) {
    if (teil.length && q([...teil, s]).length >= FILTER_QUERY_MAX) { out.push(q(teil)); teil = []; }
    teil.push(s);
  }
  if (teil.length) out.push(q(teil));
  return out;
})());
export const SENDER_QUERY = SECURITY_SENDERS.join(' OR ');

/** Zusatz für jede Gmail-Suche: schließt beide Filter-Merkmale aus. */
export const securityExclusionQuery = () => `-${SUBJECT_QUERY} -from:(${SENDER_QUERY})`;

// Wortweise wie die Gmail-Suche (reviewer S112 B1): Satzzeichen und Bindestriche sind Trenner, eine Phrase trifft nur
// ganze Wörter („one-time password“ = „one time password“, aber „2FA“ nicht in „A2FA91“). Grenzfälle, die Gmail
// anders zerlegt, sind möglich; die Suche schließt dann aus, was der Wächter nicht sperrt, oder umgekehrt (dann blendet
// access-read den Treffer aus, statt abzubrechen).
const woerter = (s) => ` ${String(s ?? '').toLowerCase().normalize('NFC').replace(/[^\p{L}\p{N}]+/gu, ' ').trim()} `;
const BETREFFE = SECURITY_SUBJECTS.map(woerter);
/** Trifft ein Merkmal zu? Betreff enthält eine Phrase (ganze Wörter) oder From enthält einen der Absender. */
export function isSecurityMail({ from, subject }) {
  const s = woerter(subject);
  const f = String(from ?? '').toLowerCase();
  return BETREFFE.some((b) => s.includes(b)) || SECURITY_SENDERS.some((x) => f.includes(x));
}
