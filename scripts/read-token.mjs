#!/usr/bin/env node
// Lese-Token (nur drive/spreadsheets/documents.readonly) für ein Konto aus read.json erzeugen (S137 „Mail-Wächter-Job
// live“; Logik und Schutz in src/token-setup.js, bewusst außerhalb von src/read (der Lese-Befehl kennt kein POST), README „Tokens erzeugen“).
//
//   node scripts/read-token.mjs start --account <name>                    zeigt die Anmelde-URL für den Inhaber
//   node scripts/read-token.mjs finish --account <name> --url-file <datei>  tauscht den Code aus der Weiterleitungs-URL
//   node scripts/read-token.mjs finish --account <name> --url '<url>'        dasselbe, URL direkt
//
// Die Token-Datei entsteht unter ~/.config/gsheets (GOOGLE_CONFIG_DIR) mit dem Namen aus read.json, Rechte 600, nie
// überschrieben. Ausgabe nie mit Token. Rückweg: nur die Datei löschen. NICHT den Zugriff der App im Google-Konto
// entziehen: gleicher OAuth-Client wie token.json, das träfe bei gleichem Konto auch den Haupt-Token (reviewer S137).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { configDir } from '../src/google-auth.js';
import { loadConfig, resolveAccount } from '../src/read/accounts.js';
import { parseArgs } from '../src/read/cli.js';
import { finishReadToken, READ_TOKEN_SCOPES, startReadToken } from '../src/token-setup.js';

const { pos, opt } = parseArgs(process.argv.slice(2), { values: ['account', 'url', 'url-file'] });
const [schritt, ...rest] = pos;
if (!['start', 'finish'].includes(schritt) || rest.length || !opt.account) {
  console.error('Aufruf: read-token.mjs start|finish --account <name> [--url <url> | --url-file <datei>]');
  process.exit(2);
}
try {
  const account = resolveAccount(loadConfig(), opt.account);
  const googleDir = process.env.GOOGLE_CONFIG_DIR || configDir();
  let client;
  // nie den Dateiinhalt in eine Meldung (Client-Secret)
  try { client = JSON.parse(readFileSync(join(googleDir, 'oauth-client.json'), 'utf8')); } catch (e) { throw new Error(`oauth-client.json nicht lesbar (${e.code ?? 'kein gültiges JSON'})`); }
  if (schritt === 'start') {
    const r = startReadToken(account, { googleDir, client });
    console.log(`Lese-Token für ${account.name} (${account.email}) → ${r.target}`);
    console.log(`Rechte: ${READ_TOKEN_SCOPES.map((s) => s.split('/').pop()).join(', ')}`);
    console.log('1. Diese Adresse im Browser öffnen, mit dem genannten Konto anmelden, zustimmen:');
    console.log(r.url);
    console.log('2. Der Browser landet auf http://127.0.0.1:8765/… („nicht erreichbar“ ist richtig). Die ganze Adresse');
    console.log(`   aus der Adresszeile kopieren und an die Session geben; die ruft dann „finish --account ${account.name}“ auf.`);
  } else {
    const url = opt['url-file'] ? readFileSync(opt['url-file'], 'utf8') : opt.url;
    if (!url) throw new Error('--url oder --url-file fehlt');
    const r = await finishReadToken(account, url, { googleDir, client });
    console.log(`✓ ${r.target} angelegt (600) für ${r.email}; Rechte: ${r.scope.split(/\s+/).map((s) => s.split('/').pop()).join(', ')}`);
    console.log(`Gegenprobe: access-read accounts --check`);
  }
} catch (e) {
  console.error(`read-token: ${String(e.message).slice(0, 300)}`);
  process.exit(1);
}
