#!/usr/bin/env node
// Sperr-Label für Sicherheitsmails in Postfächern einrichten (S112 „Ein Mail-Weg für Sessions und Agenten“, Board A694 a).
//
//   node scripts/security-label.mjs [--mailbox <adresse>]…            Dry-Run: zeigt je Postfach, was fehlt (Standard)
//   node scripts/security-label.mjs --apply [--mailbox <adresse>]…    legt nur Fehlendes an (Label, zwei Filter)
//   node scripts/security-label.mjs --rollback <stand-datei>          zeigt, was ein Lauf angelegt hat, und wie man es
//                                                                     von Hand entfernt (löscht selbst nichts)
//
// Ohne --mailbox: die Konten aus ~/.config/access-client/read.json (ACCESS_READ_CONFIG), deren Domain die
// Mail-Delegierung abdeckt. Künftige Postfächer: mit --mailbox <neue adresse> erneut laufen lassen.
// Zugang: Schlüssel aus mailDelegation.key unter ~/.config/gsheets (GOOGLE_CONFIG_DIR), Scopes gmail.labels und
// gmail.settings.basic. Sicherung: Vor jedem Live-Lauf schreibt das Skript den Vorher-Stand (Filter je Postfach) und
// nach jedem Anlegen die neuen IDs nach ~/.local/state/access-client/security-label-<zeit>.json (Rechte 600).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { configDir, getDelegatedToken } from '../src/google-auth.js';
import { applySecurityLabel, GMAIL_LABELS, GMAIL_SETTINGS_BASIC, planSecurityLabel } from '../src/gmail-setup.js';
import { loadConfig, resolveMailbox } from '../src/read/accounts.js';
import { parseArgs } from '../src/read/cli.js';

const { pos, opt } = parseArgs(process.argv.slice(2), { values: ['rollback'], multi: ['mailbox'], flags: ['apply', 'dry-run'] });
if (pos.length) { console.error(`unerwartet: ${pos[0]}`); process.exit(2); }

if (opt.rollback) {
  const s = JSON.parse(readFileSync(opt.rollback, 'utf8'));
  console.log(`Lauf ${s.zeit}: angelegt (dieses Skript löscht nichts; Entfernen von Hand in Gmail → Einstellungen → Filter bzw. Labels):`);
  for (const p of s.postfaecher ?? []) for (const c of p.created ?? []) console.log(`  ${p.mailbox}: ${c.name} ${c.id ?? ''}`);
  process.exit(0);
}

const config = loadConfig();
if (!config.mailDelegation) { console.error('mailDelegation fehlt in der Konfiguration'); process.exit(1); }
const label = config.gmailBlockedLabel;
const boxes = (opt.mailbox?.length ? opt.mailbox : Object.values(config.accounts).map((a) => a.email)
  .filter((e) => config.mailDelegation.domains.includes(e.split('@')[1]))).map((w) => resolveMailbox(config, w));
const datei = join(process.env.GOOGLE_CONFIG_DIR || configDir(), config.mailDelegation.key);
const tok = (sub, scope) => getDelegatedToken({ datei, sub, scopes: [scope], allowedScopes: [scope] });

const apply = Boolean(opt.apply);
const zeit = new Date().toISOString().replace(/[:.]/g, '-');
const stand = join(homedir(), '.local', 'state', 'access-client', `security-label-${zeit}.json`);
const protokoll = { zeit, label, postfaecher: [] };
const sichern = () => { mkdirSync(join(homedir(), '.local', 'state', 'access-client'), { recursive: true }); writeFileSync(stand, `${JSON.stringify(protokoll, null, 2)}\n`, { mode: 0o600 }); };

let fehler = 0;
for (const mb of boxes) {
  try {
    const t = { labelsToken: await tok(mb.email, GMAIL_LABELS), filtersToken: await tok(mb.email, GMAIL_SETTINGS_BASIC), mailbox: mb.email, label };
    const plan = await planSecurityLabel(t);
    if (!apply) { console.log(`${mb.email}: ${plan.missing.length ? `fehlt ${plan.missing.map((m) => m.name).join(', ')}` : 'vollständig'}`); continue; }
    protokoll.postfaecher.push({ mailbox: mb.email, before: plan.before, created: [] });
    sichern();
    const r = await applySecurityLabel(t);
    protokoll.postfaecher.at(-1).created = r.created;
    sichern();
    console.log(`${mb.email}: ${r.created.length ? `angelegt ${r.created.map((c) => c.name).join(', ')}` : 'schon vollständig'}`);
  } catch (e) { fehler++; console.error(`${mb.email}: FEHLER ${String(e.message).slice(0, 300)}`); }
}
if (apply) console.log(`Stand/Sicherung: ${stand}\nHinweis: Filter wirken nur auf neue Mails; ältere Sicherheitsmails tragen das Label nicht.`);
else console.log('Dry-Run, nichts geändert. Live: --apply');
process.exit(fehler ? 1 : 0);
