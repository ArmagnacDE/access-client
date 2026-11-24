// Merkmale von Sicherheitsmails (Passwort-Reset, Login-Codes, 2FA): EINE Liste für die Gmail-Filter der Einrichtung
// (src/gmail-setup.js) und für den Gmail-Wächter (src/gmail.js, blockSecurityContent). Quelle: Unraid openclaw/README.md
// „Gmail-Filter für Sicherheitsmails“ (S29, Board E963 a); Änderungen hier und dort gemeinsam.
// Warum auch im Wächter: Gmail-Filter wirken nur auf neue Mails, ältere Sicherheitsmails tragen das Label nicht
// (S112 „Ein Mail-Weg für Sessions und Agenten“, 24.11.2026).

export const SECURITY_SUBJECTS = Object.freeze(['password reset', 'reset your password', 'Passwort zurücksetzen', 'Passwort vergessen',
  'verification code', 'Bestätigungscode', 'Verifizierungscode', 'security code', 'Sicherheitscode', 'login code', 'Anmeldecode',
  'sign-in code', 'one-time code', 'one-time password', 'Einmalcode', 'Einmalpasswort', '2FA', 'two-factor', 'Zwei-Faktor',
  'magic link', 'Anmeldelink', 'login link', 'new sign-in', 'your code is', 'Dein Code lautet', 'Ihr Code lautet']);
/** Nur Absender, die ausschließlich Sicherheitsmails schicken (GitHub, Shopify u. ä. fängt der Betreff). */
export const SECURITY_SENDERS = Object.freeze(['accounts.google.com', 'account-security-noreply@accountprotection.microsoft.com',
  'appleid@id.apple.com', 'security@facebookmail.com']);

export const SUBJECT_QUERY = `subject:(${SECURITY_SUBJECTS.map((s) => `"${s}"`).join(' OR ')})`;
export const SENDER_QUERY = SECURITY_SENDERS.join(' OR ');

/** Zusatz für jede Gmail-Suche: schließt beide Filter-Merkmale aus. */
export const securityExclusionQuery = () => `-${SUBJECT_QUERY} -from:(${SENDER_QUERY})`;

const klein = (s) => String(s ?? '').toLowerCase().replace(/\s+/g, ' ');
const BETREFFE = SECURITY_SUBJECTS.map(klein);
/** Trifft ein Merkmal zu? Betreff enthält eine Phrase (Groß/klein und Leerraum egal) oder From enthält einen Absender. */
export function isSecurityMail({ from, subject }) {
  const s = klein(subject);
  const f = klein(from);
  return BETREFFE.some((b) => s.includes(b)) || SECURITY_SENDERS.some((x) => f.includes(x));
}
