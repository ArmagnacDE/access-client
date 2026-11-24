// Merkmale von Sicherheitsmails (Passwort-Reset, Login-Codes, 2FA): EINE Liste für die Gmail-Filter der Einrichtung
// (src/gmail-setup.js), den Gmail-Wächter (src/gmail.js, blockSecurityContent) und den Mail-Wächter (src/mail-guard.js,
// der Mails mit Merkmal, aber ohne Sperr-Label meldet und Kandidaten für diese Liste vorschlägt). Quelle: Unraid openclaw/README.md
// „Gmail-Filter für Sicherheitsmails“ (S29, Board E963 a); Änderungen hier und dort gemeinsam.
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
  'verify your email', 'neues Passwort', 'new login', 'new device', 'multi-factor', 'two-step', 'Verifizieren Sie Ihre Identität',
  'security alert', 'Sicherheitswarnung',
  'your code is', 'Dein Code lautet', 'Ihr Code lautet',
  // Ergänzung S123 (Mail-Weg Nacharbeiten): dieselben Arten aus A782 a in Varianten und auf Französisch
  'verify email', 'confirm your email', 'E-Mail-Adresse bestätigen', 'bestätige deine E-Mail', 'bestätigen Sie Ihre E-Mail',
  'vérifiez votre adresse', 'confirmez votre adresse',
  'new password', 'nouveau mot de passe', 'réinitialiser votre mot de passe', 'mot de passe oublié',
  'neue Anmeldung', 'neues Gerät', 'nouvelle connexion', 'nouvel appareil',
  '2-step', 'Multi-Faktor', 'zweistufige', 'deux facteurs', 'multifacteur',
  'verify your identity', 'Identität verifizieren', 'Identität bestätigen', 'vérifiez votre identité', 'vérifier votre identité',
  'Sicherheitshinweis', 'alerte de sécurité', 'code de vérification']);
/** Nur Absender, die ausschließlich Sicherheitsmails schicken (GitHub, Shopify u. ä. fängt der Betreff). */
export const SECURITY_SENDERS = Object.freeze(['accounts.google.com', 'account-security-noreply@accountprotection.microsoft.com',
  'appleid@id.apple.com', 'security@facebookmail.com']);

export const SUBJECT_QUERY = `subject:(${SECURITY_SUBJECTS.map((s) => `"${s}"`).join(' OR ')})`;
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
