#!/usr/bin/env node
// Sperr-Label für Sicherheitsmails in Postfächern einrichten (S112 „Ein Mail-Weg für Sessions und Agenten“, Board A694 a).
//
//   node scripts/security-label.mjs [--mailbox <adresse>]…            Dry-Run: zeigt je Postfach, was fehlt (Standard)
//   node scripts/security-label.mjs --apply [--mailbox <adresse>]…    legt nur Fehlendes an (Label, Filter)   
//   node scripts/security-label.mjs --rollback <stand-datei>          zeigt, was ein Lauf angelegt hat, und wie man es
//                                                                     von Hand entfernt (löscht selbst nichts)
//   node scripts/security-label.mjs --remove-old <stand-datei> [--apply]
//        alte Betreff-Sperrfilter früherer Listen löschen (S137): nur die aus dem Vorher-Stand dieser Datei, nur wenn
//        unverändert und die aktuellen Filter stehen; Dry-Run ist Standard. Jeder Filter wird vor dem Löschen nach
//        ~/.local/state/access-client/security-label-removed-<zeit>.json gesichert (600). Löschen = feste Grenze:
//        --apply nur mit Saschas Freigabe.
//   node scripts/security-label.mjs --restore <removed-datei> [--apply]   legt gesicherte Filter wieder an
//
// Ohne --mailbox: die Konten aus ~/.config/access-client/read.json (ACCESS_READ_CONFIG), deren Domain die
// Mail-Delegierung abdeckt. Künftige Postfächer: mit --mailbox <neue adresse> erneut laufen lassen.
// Zugang: Schlüssel aus mailDelegation.key unter ~/.config/gsheets (GOOGLE_CONFIG_DIR), Scopes gmail.labels und
// gmail.settings.basic. Sicherung: Vor jedem Live-Lauf schreibt das Skript den Vorher-Stand (Filter je Postfach) und
// nach jedem Anlegen die neuen IDs nach ~/.local/state/access-client/security-label-<zeit>.json (Rechte 600).
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { configDir, getDelegatedToken } from '../src/google-auth.js';
import { applySecurityLabel, GMAIL_LABELS, GMAIL_SETTINGS_BASIC, planSecurityLabel } from '../src/gmail-setup.js';
import { oldFilterCandidates, planFilterCleanup, removeOldFilters, restoreFilters } from '../src/gmail-filter-cleanup.js';
import { loadConfig, resolveMailbox } from '../src/read/accounts.js';
import { parseArgs } from '../src/read/cli.js';

const { pos, opt } = parseArgs(process.argv.slice(2), { values: ['rollback', 'remove-old', 'restore'], multi: ['mailbox'], flags: ['apply', 'dry-run'] });
if (pos.length) { console.error(`unerwartet: ${pos[0]}`); process.exit(2); }
if (opt.apply && opt['dry-run']) { console.error('--apply und --dry-run zusammen: unklar, nichts getan'); process.exit(2); }

if (opt.rollback) {
  const s = JSON.parse(readFileSync(opt.rollback, 'utf8'));
  console.log(`Lauf ${s.zeit}: angelegt (--rollback löscht nichts; Entfernen von Hand in Gmail → Einstellungen → Filter bzw. Labels):`);
  for (const p of s.postfaecher ?? []) for (const c of p.created ?? []) console.log(`  ${p.mailbox}: ${c.name} ${c.id ?? ''}`);
  process.exit(0);
}

const config = loadConfig();
// leerer Wert (z. B. leere Shell-Variable) darf nicht in die Einrichtung mit --apply fallen (reviewer S137)
if (opt['remove-old'] === '' || opt.restore === '' || opt.rollback === '') { console.error('Dateipfad leer: nichts getan'); process.exit(2); }
if (opt['remove-old'] || opt.restore) {
  if (opt['remove-old'] && opt.restore) { console.error('--remove-old und --restore zusammen: unklar, nichts getan'); process.exit(2); }
  if (opt['dry-run'] && opt.apply) { console.error('--apply und --dry-run zusammen: unklar, nichts getan'); process.exit(2); }
  const datei = join(process.env.GOOGLE_CONFIG_DIR || configDir(), config.mailDelegation?.key ?? '');
  const quelle = JSON.parse(readFileSync(opt['remove-old'] ?? opt.restore, 'utf8'));
  const zeit = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = join(homedir(), '.local', 'state', 'access-client');
  const sicherung = join(dir, `security-label-removed-${zeit}.json`);
  const gesichert = { zeit, quelle: opt['remove-old'] ?? null, postfaecher: [] };
  // atomar ersetzen (Codex S137): erst Temp-Datei vollständig schreiben, dann umbenennen; die alte Sicherung bleibt bis dahin heil
  const sichere = () => { mkdirSync(dir, { recursive: true }); const tmp = `${sicherung}.tmp`; writeFileSync(tmp, `${JSON.stringify(gesichert, null, 2)}\n`, { mode: 0o600 }); renameSync(tmp, sicherung); };
  // --mailbox begrenzt auch hier (Codex S137: eine auf ein Postfach begrenzte Freigabe darf nicht alle treffen)
  const auswahl = opt.mailbox?.length ? new Set(opt.mailbox.map((w) => resolveMailbox(config, w).email)) : null;
  let fehler = 0;
  for (const p of quelle.postfaecher ?? []) {
    try {
      const mb = resolveMailbox(config, p.mailbox);
      if (auswahl && !auswahl.has(mb.email)) continue;
      const token = await getDelegatedToken({ datei, sub: mb.email, scopes: [GMAIL_SETTINGS_BASIC], allowedScopes: [GMAIL_SETTINGS_BASIC] });
      if (opt.restore) {
        const r = await restoreFilters({ token, mailbox: mb.email, filters: p.filters ?? [], dryRun: !opt.apply });
        console.log(`${mb.email}: ${opt.apply ? 'angelegt' : 'würde anlegen'} ${r.created.map((c) => c.alt).join(', ') || '–'}; schon da ${r.skipped.join(', ') || '–'}`);
        continue;
      }
      const candidates = oldFilterCandidates(p);
      const zeile = (x) => `${x.id} (${[...x.criteria.query.matchAll(/"([^"]+)"/g)].length} Phrasen)`;
      if (!opt.apply) {
        const plan = await planFilterCleanup({ token, mailbox: mb.email, candidates });
        console.log(`${mb.email}: ${plan.blocked ? `GESPERRT: ${plan.blocked}` : `würde löschen ${plan.delete.map(zeile).join(', ') || '–'}`}${plan.gone.length ? `; schon weg ${plan.gone.join(', ')}` : ''}${plan.changed.length ? `; geändert, bleibt ${plan.changed.join(', ')}` : ''}`);
        continue;
      }
      const r = await removeOldFilters({ token, mailbox: mb.email, candidates,
        backup: async (liste) => { gesichert.postfaecher.push({ mailbox: mb.email, filters: liste }); sichere(); },
        onDeleted: (id) => console.log(`${mb.email}: gelöscht ${id}`) });
      if (r.blocked) { fehler++; console.error(`${mb.email}: GESPERRT ${r.blocked}`); continue; }
      console.log(`${mb.email}: gelöscht ${r.deleted.join(', ') || '–'}${r.gone.length ? `; schon weg ${r.gone.join(', ')}` : ''}${r.changed.length ? `; geändert, bleibt ${r.changed.join(', ')}` : ''}`);
    } catch (e) { fehler++; console.error(`${p.mailbox}: FEHLER ${String(e.message).slice(0, 300)}`); }
  }
  if (opt['remove-old'] && opt.apply && gesichert.postfaecher.length) console.log(`Sicherung: ${sicherung}\nRückweg: node scripts/security-label.mjs --restore ${sicherung} --apply`);
  else if (!opt.apply) console.log('Dry-Run, nichts geändert. Live: --apply');
  process.exit(fehler ? 1 : 0);
}
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
    // jede Anlage sofort sichern (Codex S112 #3: scheitert der zweite Filter, stehen Label und erster Filter im Stand)
    const r = await applySecurityLabel({ ...t, onCreated: (c) => { protokoll.postfaecher.at(-1).created.push(c); sichern(); } });
    console.log(`${mb.email}: ${r.created.length ? `angelegt ${r.created.map((c) => c.name).join(', ')}` : 'schon vollständig'}`);
  } catch (e) { fehler++; console.error(`${mb.email}: FEHLER ${String(e.message).slice(0, 300)}`); }
}
if (apply) console.log(`Stand/Sicherung: ${stand}\nHinweis: Filter wirken nur auf neue Mails; ältere Sicherheitsmails tragen das Label nicht.`);
else console.log('Dry-Run, nichts geändert. Live: --apply');
process.exit(fehler ? 1 : 0);
