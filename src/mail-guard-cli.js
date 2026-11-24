// Befehl mail-guard (S114 „Mail-Wächter: nächtliche Prüfung und 2FA-Filter nachziehen“): ruft scanMailbox je Postfach,
// meldet Befunde per ntfy und speichert den Zustand. Externe Schreibwege: genau einer, die ntfy-Meldung (POST an die
// konfigurierte URL). Gmail nur lesend (gmail.readonly, je Postfach ein delegiertes Token).
//
//   mail-guard check   [--mailbox <adresse>]… [--key <datei>] [--label <name>] [--state-dir <ordner>]
//                      [--ntfy-env <VARIABLE>] [--days <n>] [--learn-days <n>] [--dry-run]
//   mail-guard propose [--mailbox <adresse>]… [--key …] [--label …] [--days 90]
//   mail-guard accept  --mailbox <adresse> --fingerprint "<abdruck>" [--state-dir <ordner>]
//
// check: nachts. Erster Lauf je Postfach legt den Grundstand an (Einstellungen, Abdrücke der Gesendeten). Zustand wird
//   erst gespeichert, wenn die Meldung angekommen ist (sonst meldet der nächste Lauf dieselben Befunde erneut).
//   --dry-run: nichts gespeichert, nichts gemeldet, nur Ausgabe.
// propose: liest die letzten --days Tage und zeigt Kandidaten für die Merkmal-Liste (Domain, Muster, Betreffe
//   maskiert); schreibt nichts, meldet nichts. Ergänzt wird die Liste nur per PR (src/security-mail.js) und danach
//   scripts/security-label.mjs --apply, nach Freigabe.
// accept: nimmt einen Abdruck (neuer Client) in den Grundstand eines Postfachs auf (nur die lokale Zustandsdatei).
//
// Ohne --key: Schlüssel, Label und Postfächer aus der access-read-Konfiguration (mailDelegation, gmailBlockedLabel).
// Exit: 0 ok · 1 Fehler (Meldung nicht zugestellt, Aufruf falsch) · 3 ein Postfach nicht lesbar (übrige geprüft).

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { configDir, getDelegatedToken } from './google-auth.js';
import { configureGmailGuard, GMAIL_READONLY } from './gmail.js';
import { formatNotification, proposeFromFindings, scanMailbox } from './mail-guard.js';
import { loadConfig, resolveMailbox } from './read/accounts.js';
import { parseArgs, redact } from './read/cli.js';

// ⚠ im Log: was Mails nach außen bringen oder Kunden erreichen kann
const WARN = /Weiterleitung an|Weiterleitungsadresse|Delegierung an|Reply-To|Abwesenheitsnotiz an/;
export const USAGE = `mail-guard: Mail-Wächter (nur lesend; Meldung per ntfy)
  mail-guard check   [--mailbox <adresse>]… [--key <datei>] [--label <name>] [--state-dir <ordner>] [--ntfy-env <VARIABLE>] [--days <n>] [--learn-days <n>] [--dry-run]
  mail-guard propose [--mailbox <adresse>]… [--key <datei>] [--label <name>] [--days <n>]
  mail-guard accept  --mailbox <adresse> --fingerprint "<abdruck>" [--state-dir <ordner>]`;

const MAILBOX = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;
const zahl = (v, def, max) => {
  if (v == null) return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > max) throw new Error(`Zahl 1–${max} erwartet, nicht ${String(v).slice(0, 10)}`);
  return n;
};
const stateFile = (dir, mb) => join(dir, `mail-guard-${mb.replace(/[^a-z0-9@._-]/g, '_')}.json`);
function readState(dir, mb, readFile) {
  let st;
  try { st = JSON.parse(readFile(stateFile(dir, mb), 'utf8')); } catch (e) {
    if (e?.code === 'ENOENT') return null;
    throw new Error(`Zustand ${mb} nicht lesbar (${e?.code ?? e?.name}); nichts geprüft, Datei prüfen`);
  }
  // Form prüfen (reviewer S114 nice 9): ohne lastRun hieße die Suche after:NaN
  const obj = (x) => x && typeof x === 'object' && !Array.isArray(x);
  if (st?.version !== 1 || !Number.isFinite(st.lastRun) || !obj(st.settings) || !obj(st.sent?.known) || !Array.isArray(st.reported)) {
    throw new Error(`Zustand ${mb} ungültig (Version/lastRun/settings/sent/reported); nichts geprüft, Datei prüfen`);
  }
  return st;
}
/** Form eines Abdrucks wie sentFingerprint ihn baut (accept prüft, reviewer S114 nice 10). */
const FINGERPRINT = /^ua:[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)* id@[a-z0-9.#-]+ b:[^\s]+$/;
function writeState(dir, mb, state, fs) {
  fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const f = stateFile(dir, mb);
  const tmp = `${f}.tmp-${process.pid}`;
  fs.writeFile(tmp, `${JSON.stringify(state, null, 1)}\n`, { mode: 0o600 });
  fs.rename(tmp, f);
}

/** Meldung an ntfy (Titel und Priorität als URL-Parameter, damit Umlaute nicht in HTTP-Köpfen stehen). */
export async function notify(url, n, fetchImpl = fetch) {
  const u = new URL(url);
  u.searchParams.set('title', n.title);
  u.searchParams.set('priority', n.priority);
  u.searchParams.set('tags', 'lock');
  let res;
  try { res = await fetchImpl(u.href, { method: 'POST', body: n.body, signal: AbortSignal.timeout(15_000) }); } catch (e) { throw new Error(`ntfy nicht erreichbar (${e?.cause?.code ?? e?.name})`); }
  if (!res.ok) throw new Error(`ntfy lehnt ab: HTTP ${res.status}`);
}

function setup(opt, { env, readFile }) {
  if (opt.key) {
    if (!opt.label) throw new Error('--key braucht --label (Sperr-Label)');
    if (!opt.mailbox?.length) throw new Error('--key braucht mindestens ein --mailbox');
    for (const m of opt.mailbox) if (!MAILBOX.test(m)) throw new Error(`Postfach ungültig: ${String(m).slice(0, 60)}`);
    return { key: opt.key, label: opt.label, boxes: opt.mailbox };
  }
  const config = loadConfig({ env, readFile });
  if (!config.mailDelegation) throw new Error('mailDelegation fehlt in der Konfiguration (oder --key angeben)');
  const boxes = (opt.mailbox?.length ? opt.mailbox : Object.values(config.accounts).map((a) => a.email)
    .filter((e) => config.mailDelegation.domains.includes(e.split('@')[1]))).map((w) => resolveMailbox(config, w).email);
  return { key: join(env.GOOGLE_CONFIG_DIR || configDir(), config.mailDelegation.key), label: opt.label ?? config.gmailBlockedLabel, boxes };
}

/**
 * @param {string[]} argv
 * @param {{ fetchImpl?, env?, now?, log?, err?, getToken?, readFile?, fs? }} deps  für Tests
 * @returns {Promise<number>} Exit-Code
 */
export async function run(argv, deps = {}) {
  const env = deps.env ?? process.env;
  const log = deps.log ?? ((s) => console.log(s));
  const err = deps.err ?? ((s) => console.error(s));
  const readFile = deps.readFile ?? readFileSync;
  const fs = deps.fs ?? { mkdir: mkdirSync, writeFile: writeFileSync, rename: renameSync };
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now();
  let cmd; let opt;
  try {
    const a = parseArgs(argv, { values: ['key', 'label', 'state-dir', 'ntfy-env', 'days', 'learn-days', 'fingerprint'], multi: ['mailbox'], flags: ['dry-run'] });
    [cmd] = a.pos; opt = a.opt;
    if (a.pos.length !== 1 || !['check', 'propose', 'accept'].includes(cmd)) throw new Error('Unterbefehl check, propose oder accept');
  } catch (e) { err(`${e.message}\n${USAGE}`); return 1; }
  const stateDir = opt['state-dir'] ?? join(env.HOME || homedir(), '.local', 'state', 'access-client', 'mail-guard');

  if (cmd === 'accept') {
    const mb = opt.mailbox?.[0];
    if (!mb || opt.mailbox.length !== 1 || !MAILBOX.test(mb) || !opt.fingerprint) { err(`accept braucht genau ein --mailbox und --fingerprint\n${USAGE}`); return 1; }
    if (!FINGERPRINT.test(opt.fingerprint)) { err(`Abdruck „${opt.fingerprint.slice(0, 80)}“ hat nicht die Form „ua:<client> id@<host> b:<grenze>“ (aus der Meldung zwischen […] kopieren, in einfachen Anführungszeichen)`); return 1; }
    let st;
    try { st = readState(stateDir, mb, readFile); } catch (e) { err(e.message); return 1; }
    if (!st) { err(`kein Zustand für ${mb}; erst check laufen lassen`); return 1; }
    st.sent.known[opt.fingerprint] = { ...(st.sent.known[opt.fingerprint] ?? { count: 0 }), accepted: now };
    writeState(stateDir, mb, st, fs);
    log(`angenommen: ${mb} ${opt.fingerprint}`);
    return 0;
  }

  let cfg; let days; let learnDays;
  try {
    cfg = setup(opt, { env, readFile });
    days = zahl(opt.days, cmd === 'propose' ? 90 : 2, 365);
    learnDays = zahl(opt['learn-days'], 60, 365);
    // Sperr-Label streng: fehlt es, liest kein Inhaltspfad. Merkmal-Sperre aus: der Wächter soll gerade die Mails mit
    // Merkmal, aber ohne Label finden; er liest nur From/Subject (metadata), gibt keinen Inhalt aus.
    configureGmailGuard({ blockedLabel: cfg.label, requireLabel: true, blockSecurityContent: false });
  } catch (e) { err(`mail-guard: ${redact(e.message)}`); return 1; }
  const getToken = deps.getToken ?? ((sub) => getDelegatedToken({ datei: cfg.key, sub, scopes: [GMAIL_READONLY], allowedScopes: [GMAIL_READONLY], fetchImpl }));

  const results = [];
  let unlesbar = 0;
  for (const mb of cfg.boxes) {
    try {
      const state = cmd === 'propose' ? null : readState(stateDir, mb, readFile);
      // propose: wie ein Grundstand-Lauf über --days (lernt nur, meldet Kandidaten); nie gespeichert
      const r = await scanMailbox({ token: await getToken(mb), mailbox: mb, state, now, days, learnDays: cmd === 'propose' ? 1 : learnDays, maxMessages: cmd === 'propose' ? 2000 : 1000, fetchImpl });
      results.push(r);
      if (r.incomplete) unlesbar++;
      log(`${mb}: ${r.baseline && cmd === 'check' ? 'Grundstand angelegt · ' : ''}${Object.entries(r.counts).map(([k, v]) => `${k} ${v}`).join(' · ')}${r.truncated ? ' · gekürzt (zu viele Treffer)' : ''}`);
      // Was der Grundstand ungemeldet übernimmt, sichtbar machen (reviewer S114 B5): Sascha prüft daran die Probe.
      // Datensparsam wie die Meldung (Abdrücke, Kurztexte mit Domain); ⚠ = genau hinsehen.
      if (r.baseline && cmd === 'check' && r.state) {
        for (const [fp, v] of Object.entries(r.state.sent.known).sort((a, b) => b[1].count - a[1].count)) {
          log(`${mb}: gelernt Abdruck ${v.count}× ${fp}${/^ua:- .* b:-$/.test(fp) ? ' ⚠ einteilig ohne Client, so sieht auch Skript-Versand aus' : ''}`);
        }
        for (const v of Object.values(r.state.settings)) {
          log(`${mb}: gelernt ${v.summary}${WARN.test(v.summary) ? ' ⚠' : ''}`);
        }
      }
      // Update eines älteren Zustands: neue Bereiche werden still übernommen; sichtbar machen (reviewer S123 nice 3)
      for (const v of r.learned ?? []) log(`${mb}: gelernt (Update) ${v.summary}${WARN.test(v.summary) ? ' ⚠' : ''}`);
    } catch (e) {
      unlesbar++;
      const grund = redact(String(e?.message)).slice(0, 300);
      err(`${mb}: NICHT GEPRÜFT ${grund}`);
      // in die Meldung, damit ein Ausfall nicht nur im Log steht (Codex S114 #4); kein Zustand für dieses Postfach
      results.push({ mailbox: mb, findings: [{ kind: 'error', detail: grund.slice(0, 120) }], state: null });
    }
  }

  if (cmd === 'propose') {
    const p = proposeFromFindings(results);
    log(JSON.stringify({ vorschlag: p, hinweis: 'Nur Domain, Muster und maskierte Betreffe. Ergänzung der Liste per PR (src/security-mail.js), dann scripts/security-label.mjs --apply, nach Freigabe.' }, null, 1));
    return unlesbar ? 3 : 0;
  }

  const n = formatNotification(results);
  if (n) log(`${n.title}\n${n.lines.join('\n')}`);
  else log('Mail-Wächter: keine Befunde');
  const varName = opt['ntfy-env'] ?? 'MAIL_GUARD_NTFY_URL';
  const url = env[varName];
  if (opt['dry-run']) {
    // sonst fiele ein leeres ntfy-Ziel erst im echten Lauf auf (Exit 1, und der Runner meldet über dasselbe Ziel)
    if (!url) err(`WARNUNG: ${varName} nicht gesetzt; der echte Lauf könnte Befunde nicht melden`);
    log('Dry-Run: nichts gespeichert, nichts gemeldet');
    return unlesbar ? 3 : 0;
  }
  if (n) {
    if (!url) { err(`mail-guard: ${varName} nicht gesetzt; Befunde nicht gemeldet, Zustand nicht gespeichert`); return 1; }
    try { await notify(url, n, fetchImpl); } catch (e) { err(`mail-guard: ${e.message}; Zustand nicht gespeichert (nächster Lauf meldet erneut)`); return 1; }
  }
  for (const r of results) if (r.state) writeState(stateDir, r.mailbox, r.state, fs);
  return unlesbar ? 3 : 0;
}
