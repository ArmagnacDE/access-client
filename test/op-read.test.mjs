// opRead / opVaultGet (src/op-read.js) mit Fake-exec: kein echtes op, kein Netz.
import test from 'node:test';
import assert from 'node:assert/strict';
import { opRead, opVaultGet, opVaultList, opWhoami, opSelf, opItemHead, opItemOtp, vaultGetMit, pruefeVerweis, schwaerze, opUmgebung, einordnen, OpReadError, OpItemMissingError, OpItemAmbiguousError } from '../src/op-read.js';
import { tresorSuche } from '../src/op-vault.js';

const TOKEN = 'ops_' + 'A'.repeat(40);
const GEHEIM = 'sehr-geheimer-wert-123';

/** Fake-exec: zeichnet Aufrufe auf, antwortet mit antwort(args) → { err?, stdout?, stderr? }. */
function fake(antwort) {
  const aufrufe = [];
  const exec = (cmd, args, opts, cb) => {
    aufrufe.push({ cmd, args, opts });
    const a = antwort(args) ?? {};
    queueMicrotask(() => cb(a.err ?? null, Buffer.from(a.stdout ?? ''), Buffer.from(a.stderr ?? '')));
  };
  return { exec, aufrufe };
}
const fehler = (extra = {}) => Object.assign(new Error('Command failed'), { code: 1 }, extra);

test('opRead: argv nur read --no-newline <ref>, Umgebung genau PATH/HOME/Token, Buffer zurück', async () => {
  const f = fake(() => ({ stdout: GEHEIM }));
  const wert = await opRead({ ref: 'op://team-kasse/eintrag-a/credential', token: TOKEN, exec: f.exec, path: '/x/bin', home: '/home/test' });
  assert.ok(Buffer.isBuffer(wert));
  assert.equal(wert.toString(), GEHEIM);
  assert.equal(f.aufrufe.length, 1);
  const { cmd, args, opts } = f.aufrufe[0];
  assert.equal(cmd, 'op');
  assert.deepEqual(args, ['read', '--no-newline', 'op://team-kasse/eintrag-a/credential']);
  assert.deepEqual(opts.env, { PATH: '/x/bin', HOME: '/home/test', OP_SERVICE_ACCOUNT_TOKEN: TOKEN });
  assert.equal(opts.encoding, 'buffer');
  assert.equal(opts.timeout, 30_000);
  assert.ok(!args.join(' ').includes(TOKEN), 'Token nie in argv');
  assert.equal(process.env.OP_SERVICE_ACCOUNT_TOKEN === TOKEN, false, 'Token nicht in process.env');
});

test('opRead: Verweis mit Abschnitt erlaubt; Unsinn, Optionen und ?-Parameter abgelehnt, ohne op-Aufruf', async () => {
  assert.deepEqual(pruefeVerweis('op://Zoll/EINTRAG/Abschnitt/password'), ['Zoll', 'EINTRAG', 'Abschnitt', 'password']);
  assert.deepEqual(pruefeVerweis('op://team-zoll/Zertifikat Beispiel.example/password'), ['team-zoll', 'Zertifikat Beispiel.example', 'password']);
  const f = fake(() => ({ stdout: 'x' }));
  for (const ref of ['', 'team-kasse/x/y', '--help', 'op://a/b', 'op://a/b/c/d/e', 'op://a/b/c?attribute=otp', 'op://a/b/c\n', 'op://a//c', 'op://a/ b/c', 'op://a/b/' + 'x'.repeat(200), null, 42]) {
    await assert.rejects(opRead({ ref, token: TOKEN, exec: f.exec }), OpReadError, String(ref));
  }
  assert.equal(f.aufrufe.length, 0);
});

test('opRead: Token fehlt oder falsche Form → Fehler ohne Wert, kein op-Aufruf', async () => {
  const f = fake(() => ({ stdout: 'x' }));
  for (const token of [undefined, '', 'abc', 'ops_kurz', `${TOKEN}\n`]) {
    const e = await opRead({ ref: 'op://a/b/c', token, exec: f.exec }).catch((x) => x);
    assert.ok(e instanceof OpReadError);
    if (token) assert.ok(!e.message.includes(token.trim()));
  }
  assert.equal(f.aufrufe.length, 0);
});

test('opRead: Eintrag fehlt / Feld fehlt / Tresor fehlt → OpItemMissingError mit was, auch hinter einer Hinweiszeile', async () => {
  const faelle = [
    ['[ERROR] 2026/11/15 10:00:00 "eintrag-a" isn\'t an item in the "team-kasse" vault. Specify the item with its UUID, name, or domain.', 'eintrag'],
    ["[ERROR] 2026/11/15 10:00:00 could not read secret 'op://team-buch/eintrag-b/token': item 'team-buch/eintrag-b' does not have a field 'token'", 'feld'],
    ['[ERROR] 2026/11/15 10:00:00 "team-kasse" isn\'t a vault in this account. Specify the vault with its ID or name.', 'tresor'],
    ['Hinweis: neue Version verfügbar\n[ERROR] 2026/11/15 10:00:00 "x" isn\'t an item in the "v" vault.', 'eintrag'],
  ];
  for (const [stderr, was] of faelle) {
    const f = fake(() => ({ err: fehler(), stderr }));
    const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }).catch((x) => x);
    assert.ok(e instanceof OpItemMissingError, stderr);
    assert.ok(e instanceof OpReadError);
    assert.equal(e.was, was);
  }
});

test('opRead: anderer Fehler → OpReadError, nur erste Zeile, ohne [ERROR]-Kopf; stderr nicht aufzählbar', async () => {
  const stderr = '[ERROR] 2026/11/15 10:00:00 Too many requests. Rate limit exceeded.\nzweite Zeile mit Details';
  const f = fake(() => ({ err: fehler(), stderr }));
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(!(e instanceof OpItemMissingError));
  assert.equal(e.message, '1Password: Lesen fehlgeschlagen: Too many requests. Rate limit exceeded.');
  assert.ok(e.opStderr.includes('zweite Zeile'));
  assert.ok(!Object.keys(e).includes('opStderr'));
  assert.ok(!JSON.stringify(e).includes('zweite Zeile'));
});

test('opRead: stdout erscheint nie in einer Meldung, Token wird geschwärzt', async () => {
  const f = fake(() => ({ err: fehler(), stdout: GEHEIM, stderr: `[ERROR] 2026/11/15 10:00:00 invalid token ${TOKEN} und ops_${'b'.repeat(30)}` }));
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  for (const text of [e.message, e.opStderr, e.stack]) {
    assert.ok(!text.includes(GEHEIM), 'kein stdout');
    assert.ok(!text.includes(TOKEN), 'kein Token');
    assert.ok(!/ops_b{8}/.test(text), 'keine ops_-Form');
  }
  assert.match(e.message, /\[token\]/);
});

test('opRead: Zeitüberschreitung, fehlendes op, zu große Ausgabe, leeres stderr', async () => {
  const fall = async (err, stderr = '') => opRead({ ref: 'op://v/x/y', token: TOKEN, exec: fake(() => ({ err, stderr })).exec, timeoutMs: 5000 }).catch((x) => x);
  assert.match((await fall(fehler({ killed: true, signal: 'SIGTERM', code: null }))).message, /Zeitüberschreitung nach 5 s/);
  assert.match((await fall(fehler({ code: 'ENOENT' }))).message, /op-CLI nicht gefunden/);
  assert.match((await fall(fehler({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }))).message, /Ausgabe zu groß \(mehr als 65536 Byte\)$/);
  assert.match((await fall(fehler({ code: 6 }))).message, /Exit 6/);
  // exec wirft synchron (z. B. ungültige Optionen): als OpReadError, kein unbehandelter Fehler.
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: () => { throw Object.assign(new Error('spawn EACCES'), { code: 'EACCES' }); } }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.match(e.message, /op nicht ausführbar \(EACCES\)/);
});

test('opVaultGet: argv, JSON → { id, name }; ungültiger Name ohne Aufruf; kaputtes JSON', async () => {
  const f = fake(() => ({ stdout: JSON.stringify({ id: 'abc123', name: 'team-kasse', content_version: 3, extra: GEHEIM }) }));
  assert.deepEqual(await opVaultGet({ vault: 'team-kasse', token: TOKEN, exec: f.exec }), { id: 'abc123', name: 'team-kasse' });
  assert.deepEqual(f.aufrufe[0].args, ['vault', 'get', 'team-kasse', '--format', 'json']);
  await assert.rejects(opVaultGet({ vault: '-x', token: TOKEN, exec: f.exec }), OpReadError);
  await assert.rejects(opVaultGet({ vault: 'a/b', token: TOKEN, exec: f.exec }), OpReadError);
  assert.equal(f.aufrufe.length, 1);
  const kaputt = fake(() => ({ stdout: `kein json ${GEHEIM}` }));
  const e = await opVaultGet({ vault: 'team-kasse', token: TOKEN, exec: kaputt.exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(!e.message.includes(GEHEIM));
});

test('opVaultGet als vaultGet für tresorSuche: „isn\'t a vault“ führt zur anderen Schreibweise', async () => {
  const f = fake((args) => (args[2] === 'kasse'
    ? { stdout: JSON.stringify({ id: 'v1', name: 'kasse' }) }
    : { err: fehler(), stderr: `[ERROR] 2026/11/15 10:00:00 "${args[2]}" isn't a vault in this account. Specify the vault with its ID or name.` }));
  const suche = tresorSuche({ vaultGet: vaultGetMit(TOKEN, { exec: f.exec }), prefix: 'team-' });
  assert.deepEqual(await suche.tresore('team-kasse'), ['kasse']);
  assert.deepEqual(f.aufrufe.map((a) => a.args[2]), ['team-kasse', 'kasse']);
});

test('opVaultGet: anderer Fehler stoppt tresorSuche (kein Ausweichen)', async () => {
  const f = fake(() => ({ err: fehler(), stderr: '[ERROR] 2026/11/15 10:00:00 Too many requests' }));
  const suche = tresorSuche({ vaultGet: vaultGetMit(TOKEN, { exec: f.exec }), prefix: 'team-' });
  await assert.rejects(suche.tresore('team-kasse'), /scheiterte ohne die bekannte Meldung/);
  assert.equal(f.aufrufe.length, 1);
});

test('Hilfen: schwaerze und opUmgebung', () => {
  assert.equal(schwaerze(`a ${TOKEN} b`, TOKEN), 'a [token] b');
  assert.equal(schwaerze('x ops_abcdefghij y'), 'x [token] y');
  assert.deepEqual(opUmgebung(TOKEN, { env: {}, home: '/h' }), { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/h', OP_SERVICE_ACCOUNT_TOKEN: TOKEN });
});

test('opItemHead: nur ID, Titel, Feldnamen; Werte nie; Puffer genullt', async () => {
  let gegeben;
  const exec = (cmd, args, opts, cb) => {
    gegeben = Buffer.from(JSON.stringify({ id: 'it1', title: 'Eintrag-C', fields: [{ label: 'password', value: GEHEIM }, { label: 'username', value: 'u' }, { id: 'x' }] }));
    queueMicrotask(() => cb(null, gegeben, Buffer.alloc(0)));
  };
  const kopf = await opItemHead({ vault: 'team-buch', item: 'Eintrag-C', token: TOKEN, exec });
  assert.deepEqual(kopf, { id: 'it1', title: 'Eintrag-C', fieldLabels: ['password', 'username'] });
  assert.ok(!JSON.stringify(kopf).includes(GEHEIM));
  assert.ok(gegeben.every((b) => b === 0), 'Antwortpuffer genullt');
});

test('opItemHead: argv, Mehrdeutig/fehlt als eigene Klassen, kaputtes JSON ohne Zitat, ungültiger Name ohne Aufruf', async () => {
  const f = fake(() => ({ stdout: JSON.stringify({ id: 'a', title: 'b' }) }));
  await opItemHead({ vault: 'v', item: 'Eintrag mit Leerzeichen', token: TOKEN, exec: f.exec });
  assert.deepEqual(f.aufrufe[0].args, ['item', 'get', 'Eintrag mit Leerzeichen', '--vault', 'v', '--format', 'json']);
  for (const item of ['-x', '', ' a', 'a\nb', 'x'.repeat(129), 7]) await assert.rejects(opItemHead({ vault: 'v', item, token: TOKEN, exec: f.exec }), OpReadError);
  assert.equal(f.aufrufe.length, 1);
  const doppelt = fake(() => ({ err: fehler(), stderr: '[ERROR] 2026/11/15 10:00:00 More than one item matches "Eintrag-C". Try again and specify the item by its ID' }));
  await assert.rejects(opItemHead({ vault: 'v', item: 'Eintrag-C', token: TOKEN, exec: doppelt.exec }), OpItemAmbiguousError);
  const fehlt = fake(() => ({ err: fehler(), stderr: '[ERROR] 2026/11/15 10:00:00 "Eintrag-C" isn\'t an item in the "v" vault.' }));
  const e = await opItemHead({ vault: 'v', item: 'Eintrag-C', token: TOKEN, exec: fehlt.exec }).catch((x) => x);
  assert.ok(e instanceof OpItemMissingError);
  assert.equal(e.was, 'eintrag');
  const kaputt = fake(() => ({ stdout: `{"id":"a","password":"${GEHEIM}"` }));
  const k = await opItemHead({ vault: 'v', item: 'Eintrag-C', token: TOKEN, exec: kaputt.exec }).catch((x) => x);
  assert.ok(k instanceof OpReadError);
  assert.ok(!k.message.includes(GEHEIM));
});

test('opItemOtp: argv mit --otp, nur Ziffern, sonst Fehler ohne Wert', async () => {
  const ID = 'abcdefghijklmnopqrstuvwxyz';
  const f = fake(() => ({ stdout: '123456\n' }));
  assert.equal((await opItemOtp({ vault: 'v', itemId: ID, token: TOKEN, exec: f.exec })).toString(), '123456');
  assert.deepEqual(f.aufrufe[0].args, ['item', 'get', ID, '--vault', 'v', '--otp']);
  for (const itemId of ['Eintrag-C', 'it1', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', undefined]) await assert.rejects(opItemOtp({ vault: 'v', itemId, token: TOKEN, exec: f.exec }), /nur mit Eintrags-ID/);
  assert.equal(f.aufrufe.length, 1);
  const falsch = fake(() => ({ stdout: GEHEIM }));
  const e = await opItemOtp({ vault: 'v', itemId: ID, token: TOKEN, exec: falsch.exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(!e.message.includes(GEHEIM));
});

// ---------- Befunde Codex (Cross-Review 15.11.) ----------

test('Codex B1: stdout wird im Fehlerpfad genullt (abgebrochene Antwort mit Werten)', async () => {
  let gegeben;
  const exec = (cmd, args, opts, cb) => {
    gegeben = Buffer.from(JSON.stringify({ id: 'x', fields: [{ label: 'p', value: GEHEIM }] }));
    queueMicrotask(() => cb(fehler({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }), gegeben, Buffer.alloc(0)));
  };
  const e = await opItemHead({ vault: 'v', item: 'x', token: TOKEN, exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(gegeben.every((b) => b === 0));
  assert.ok(!String(e.stack).includes(GEHEIM));
});

test('Codex B2: Token als Tresorname erscheint in keiner Meldung', async () => {
  const f = fake(() => ({ stdout: '{}' }));
  for (const fn of [opVaultGet, opItemHead, opItemOtp]) {
    const e = await fn({ vault: `${TOKEN}/`, item: 'x', token: TOKEN, exec: f.exec }).catch((x) => x);
    assert.ok(e instanceof OpReadError);
    assert.ok(!String(e.stack).includes('ops_'), fn.name);
    assert.equal(e.cause, undefined);
  }
  assert.equal(f.aufrufe.length, 0);
});

test('Codex B3: Prozessfehler gehen vor; tresorSuche stoppt bei Zeitüberschreitung trotz „isn\'t a vault“ im stderr', async () => {
  const f = fake(() => ({ err: fehler({ killed: true, signal: 'SIGTERM', code: null }), stderr: '[ERROR] 2026/11/15 10:00:00 "team-v" isn\'t a vault in this account.' }));
  const e = await opVaultGet({ vault: 'team-v', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.ok(!(e instanceof OpItemMissingError));
  assert.match(e.message, /Zeitüberschreitung/);
  const suche = tresorSuche({ vaultGet: vaultGetMit(TOKEN, { exec: f.exec }), prefix: 'team-' });
  await assert.rejects(suche.tresore('team-v'), /scheiterte ohne die bekannte Meldung/);
  assert.equal(f.aufrufe.length, 2, 'nur der eine Abruf der Suche, kein Ausweichen');
});

test('Codex B3: lange Hinweisausgabe vor der Meldung → trotzdem tresor, tresorSuche weicht aus', async () => {
  const hinweis = `Hinweis: ${'x'.repeat(5000)}\n`;
  const f = fake((args) => (args[2] === 'v' ? { stdout: JSON.stringify({ id: 'i', name: 'v' }) } : { err: fehler(), stderr: `${hinweis}[ERROR] 2026/11/15 10:00:00 "${args[2]}" isn't a vault in this account.` }));
  const suche = tresorSuche({ vaultGet: vaultGetMit(TOKEN, { exec: f.exec }), prefix: 'team-' });
  assert.deepEqual(await suche.tresore('team-v'), ['v']);
});

test('Codex B4 / Fable 1: bekannte Namen werden wörtlich entfernt, Zitatzeichen im Namen stören nicht', () => {
  const art = (t, namen) => einordnen(t, namen).art;
  assert.equal(art('[ERROR] 2026/11/15 10:00:00 More than one item matches "isn\'t a vault in this account". Try again and specify the item by its ID', ['v', "isn't a vault in this account"]), 'mehrdeutig');
  assert.equal(art('[ERROR] 2026/11/15 10:00:00 "does not have a field" isn\'t an item in the "v" vault.', ['v', 'does not have a field']), 'eintrag');
  const ref = "op://v/isn't an item/x";
  assert.equal(art(`[ERROR] 2026/11/15 10:00:00 could not read secret '${ref}': item 'v/isn't an item' does not have a field 'x'`, [ref, 'v/isn\'t an item/x', "v/isn't an item", 'v', "isn't an item", 'x']), 'feld');
  assert.equal(art('[ERROR] 2026/11/15 10:00:00 "More than one item matches" isn\'t a vault in this account.', ['More than one item matches']), 'tresor');
  // Fable 1: ungerade Zahl von " im Titel war nach dem ersten Fix eine Regression.
  assert.equal(art('[ERROR] 2026/11/15 10:00:00 "27" Zoll Bildschirm" isn\'t an item in the "v" vault.', ['v', '27" Zoll Bildschirm']), 'eintrag');
  // Name mit Wortlaut und Zitatzeichen: kein falsches Ausweichen.
  const boese = 'x" isn\'t a vault in this account "y';
  assert.equal(art(`[ERROR] 2026/11/15 10:00:00 More than one vault matches "${boese}".`, [boese]), 'mehrdeutig');
  assert.equal(art('[ERROR] Too many requests'), null);
  // verschachtelte Form von op read
  assert.equal(art(`[ERROR] 2026/11/15 10:00:00 could not read secret 'op://team-kasse/x/credential': could not get item team-kasse/x: "x" isn't an item in the "team-kasse" vault`, ['op://team-kasse/x/credential', 'team-kasse', 'x', 'credential']), 'eintrag');
});

test('Codex N1: [ERROR]-Kopf ohne Zeitstempel kürzt keine Wörter', async () => {
  const f = fake(() => ({ err: fehler(), stderr: '[ERROR] Too many requests' }));
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.equal(e.message, '1Password: Lesen fehlgeschlagen: Too many requests');
});

// ---------- Befunde Fable (Cross-Review 15.11.) ----------

test('Fable 1: sehr lange stderr-Zeile wird nicht eingeordnet (keine Rechenzeitfalle)', () => {
  const t0 = Date.now();
  const r = einordnen(`[ERROR] ${" 'a".repeat(40000)} isn't a vault in this account`);
  assert.equal(r.art, null);
  assert.ok(Date.now() - t0 < 500);
});

test('Fable 2: Tod durch ein Signal ist ein Prozessfehler, tresorSuche weicht nicht aus', async () => {
  for (const signal of ['SIGKILL', 'SIGINT', 'SIGHUP']) {
    const f = fake(() => ({ err: fehler({ signal, code: null, killed: false }), stderr: '[ERROR] 2026/11/15 10:00:00 "team-v" isn\'t a vault in this account.' }));
    const suche = tresorSuche({ vaultGet: vaultGetMit(TOKEN, { exec: f.exec }), prefix: 'team-' });
    await assert.rejects(suche.tresore('team-v'), new RegExp(`beendet durch ${signal}`));
    assert.equal(f.aufrufe.length, 1);
  }
});

test('Fable 3: nur [ERROR]-Zeilen zählen; Meldung aus der eingeordneten bzw. ersten [ERROR]-Zeile; Widerspruch = Stopp', async () => {
  assert.deepEqual(einordnen('Hinweis: "v" isn\'t a vault in this account\n[ERROR] 2026/11/15 10:00:00 Too many requests'), { art: null, zeile: '[ERROR] 2026/11/15 10:00:00 Too many requests' });
  assert.equal(einordnen('[ERROR] 2026/11/15 10:00:00 Too many requests\n[ERROR] 2026/11/15 10:00:00 "v" isn\'t a vault in this account.', ['v']).art, 'tresor');
  assert.equal(einordnen('[ERROR] 2026/11/15 10:00:00 "x" isn\'t an item in the "v" vault.\n[ERROR] 2026/11/15 10:00:00 "v" isn\'t a vault in this account.', ['x', 'v']).art, null);
  const f = fake(() => ({ err: fehler(), stderr: 'Hinweis: update verfügbar\n[ERROR] 2026/11/15 10:00:00 Too many requests' }));
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.equal(e.message, '1Password: Lesen fehlgeschlagen: Too many requests');
});

test('Fable 4: tokenartige Namen nie in argv (Tresor, Eintrag, Verweis), auch ohne „/“', async () => {
  const f = fake(() => ({ stdout: '{"id":"a","name":"b"}' }));
  const kurz = 'ops_' + 'Z'.repeat(30);
  await assert.rejects(opVaultGet({ vault: kurz, token: TOKEN, exec: f.exec }), /Tresorname ungültig \(Wert nicht ausgegeben\)/);
  await assert.rejects(opVaultGet({ vault: TOKEN, token: TOKEN, exec: f.exec }), OpReadError);
  await assert.rejects(opItemHead({ vault: 'v', item: kurz, token: TOKEN, exec: f.exec }), /Eintragsname ungültig/);
  await assert.rejects(opRead({ ref: `op://v/${kurz}/password`, token: TOKEN, exec: f.exec }), /op-Verweis ungültig/);
  assert.equal(f.aufrufe.length, 0);
});

test('Fable 5: Schwärzen erfasst ops_-Formen mit + und /', () => {
  assert.equal(schwaerze('x ops_eyJabc+DEFGHIJKLMNOP/QRSTUVWXYZ0123456789== y'), 'x [token] y');
});

test('Fable 7: opItemOtp bei längerem stderr ordnet weiter ein (Limit 16 kB)', async () => {
  const f = fake(() => ({ err: fehler(), stderr: `${'h'.repeat(2000)}\n[ERROR] 2026/11/15 10:00:00 "abcdefghijklmnopqrstuvwxyz" isn't an item in the "v" vault.` }));
  const e = await opItemOtp({ vault: 'v', itemId: 'abcdefghijklmnopqrstuvwxyz', token: TOKEN, exec: f.exec }).catch((x) => x);
  assert.ok(e instanceof OpItemMissingError);
  assert.equal(f.aufrufe[0].opts.maxBuffer, 16 * 1024);
});

test('Fable 8: PATH ist fest, nicht geerbt', async () => {
  const f = fake(() => ({ stdout: 'x' }));
  const alt = process.env.PATH;
  process.env.PATH = '/tmp/node_modules/.bin:/usr/bin';
  try { await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }); } finally { process.env.PATH = alt; }
  assert.equal(f.aufrufe[0].opts.env.PATH, '/usr/local/bin:/usr/bin:/bin');
});

test('Fable 9: leerer Wert bei Exit 0 ist ein Fehler', async () => {
  const f = fake(() => ({ stdout: '' }));
  await assert.rejects(opRead({ ref: 'op://v/x/y', token: TOKEN, exec: f.exec }), /leeren Wert/);
});

test('S51: Ausgabe-Limit mit killed (Prozess nach dem Limit beendet) ist keine Zeitüberschreitung', async () => {
  // execFile beendet den Kindprozess beim Ausgabe-Limit; trägt der Fehler dabei killed/SIGTERM, zählt der Code.
  const err = fehler({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true, signal: 'SIGTERM' });
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, timeoutMs: 5000,
    exec: fake(() => ({ err, stderr: '[ERROR] 2026/11/25 10:00:00 "v" isn\'t a vault in this account.' })).exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(!(e instanceof OpItemMissingError));
  assert.doesNotMatch(e.message, /Zeitüberschreitung/);
  assert.equal(e.message, '1Password: Lesen fehlgeschlagen: Ausgabe zu groß (mehr als 65536 Byte)');
  // ETIMEDOUT bleibt Zeitüberschreitung, auch ohne killed.
  const z = await opRead({ ref: 'op://v/x/y', token: TOKEN, timeoutMs: 5000, exec: fake(() => ({ err: fehler({ code: 'ETIMEDOUT' }) })).exec }).catch((x) => x);
  assert.match(z.message, /Zeitüberschreitung nach 5 s$/);
});

test('S51 reviewer: Überlauf auf stderr heißt „Fehlerausgabe zu groß“, nicht „Ausgabe zu groß“ (Wert selbst ist nicht zu groß)', async () => {
  const err = Object.assign(new RangeError('stderr maxBuffer length exceeded'), { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' });
  const e = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: fake(() => ({ err })).exec }).catch((x) => x);
  assert.equal(e.message, '1Password: Lesen fehlgeschlagen: Fehlerausgabe zu groß (mehr als 65536 Byte)');
  const { execFile } = await import('node:child_process');
  const echt = await opRead({ ref: 'op://v/x/y', token: TOKEN, maxBytes: 100,
    exec: (cmd, args, opts, cb) => execFile(process.execPath, ['-e', 'process.stderr.write("x".repeat(1000))'], { ...opts, env: { ...opts.env, PATH: process.env.PATH } }, cb) }).catch((x) => x);
  assert.match(echt.message, /: Fehlerausgabe zu groß \(mehr als 100 Byte\)$/);
});

test('Fable 11: echtes execFile (node als op-Ersatz): Umgebung, Zeitüberschreitung, Ausgabelimit, Exit-Code', async () => {
  const { execFile } = await import('node:child_process');
  const als = (skript) => (cmd, args, opts, cb) => execFile(process.execPath, ['-e', skript], { ...opts, env: { ...opts.env, PATH: process.env.PATH } }, cb);
  // Umgebung: genau HOME, OP_SERVICE_ACCOUNT_TOKEN, PATH (PATH hier für node ersetzt, Schlüssel bleiben gleich)
  const env = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: als('process.stdout.write(Object.keys(process.env).sort().join(","))') });
  assert.equal(env.toString(), 'HOME,OP_SERVICE_ACCOUNT_TOKEN,PATH');
  const zeit = await opRead({ ref: 'op://v/x/y', token: TOKEN, timeoutMs: 300, exec: als('process.stderr.write("[ERROR] 2026/11/15 10:00:00 \\"v\\" isn\'t a vault in this account."); setTimeout(() => {}, 5000)') }).catch((x) => x);
  assert.ok(!(zeit instanceof OpItemMissingError));
  assert.match(zeit.message, /Zeitüberschreitung/);
  const gross = await opRead({ ref: 'op://v/x/y', token: TOKEN, maxBytes: 100, exec: als('process.stdout.write("x".repeat(1000))') }).catch((x) => x);
  assert.match(gross.message, /Ausgabe zu groß \(mehr als 100 Byte\)$/);
  const fehlt = await opRead({ ref: 'op://v/x/y', token: TOKEN, exec: als('process.stderr.write("[ERROR] 2026/11/15 10:00:00 \\"x\\" isn\'t an item in the \\"v\\" vault.\\n"); process.exit(1)') }).catch((x) => x);
  assert.ok(fehlt instanceof OpItemMissingError);
  assert.equal(fehlt.was, 'eintrag');
});

// S110 (Diagnose Konten und Scopes): Tresorliste und Kontoangabe eines Service-Account-Tokens, nur Namen.
test('opVaultList: argv vault list --format json, nur Namen (sortiert), keine IDs oder weiteren Felder', async () => {
  const f = fake(() => ({ stdout: JSON.stringify([
    { id: 'abcdefghijklmnopqrstuvwxyz', name: 'ai-zwei', content_version: 3, items: 4 },
    { id: 'bbcdefghijklmnopqrstuvwxyz', name: 'ai-eins', content_version: 1 },
  ]) }));
  const r = await opVaultList({ token: TOKEN, exec: f.exec, home: '/home/test' });
  assert.deepEqual(r, ['ai-eins', 'ai-zwei']);
  assert.deepEqual(f.aufrufe[0].args, ['vault', 'list', '--format', 'json']);
  assert.deepEqual(f.aufrufe[0].opts.env, { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/home/test', OP_SERVICE_ACCOUNT_TOKEN: TOKEN });
});

test('opVaultList: kein JSON-Array, Namen mit Steuerzeichen oder op-Fehler → OpReadError ohne Token', async () => {
  await assert.rejects(opVaultList({ token: TOKEN, exec: fake(() => ({ stdout: '{"a":1}' })).exec }), /keine Tresorliste/);
  await assert.rejects(opVaultList({ token: TOKEN, exec: fake(() => ({ stdout: 'kaputt' })).exec }), /keine Tresorliste/);
  await assert.rejects(opVaultList({ token: TOKEN, exec: fake(() => ({ stdout: JSON.stringify([{ id: 'x', name: 'a\nb' }]) })).exec }), /keine Tresorliste/);
  const e = await opVaultList({ token: TOKEN, exec: fake(() => ({ err: fehler(), stderr: `[ERROR] 2026/11/24 10:00:00 invalid token ${TOKEN}` })).exec }).catch((x) => x);
  assert.ok(e instanceof OpReadError);
  assert.ok(!e.message.includes(TOKEN));
  const f = fake(() => ({ stdout: '[]' }));
  await assert.rejects(opVaultList({ token: 'kein-token', exec: f.exec }), OpReadError);
  assert.equal(f.aufrufe.length, 0);
});

test('opWhoami: argv whoami --format json, nur Typ, Adresse und Konto-URL', async () => {
  const f = fake(() => ({ stdout: JSON.stringify({ url: 'https://beispiel.1password.eu', email: 'abc@beispiel.1passwordserviceaccounts.eu', user_uuid: 'U1', account_uuid: 'A1', user_type: 'SERVICE_ACCOUNT' }) }));
  const r = await opWhoami({ token: TOKEN, exec: f.exec });
  assert.deepEqual(r, { typ: 'SERVICE_ACCOUNT', email: 'abc@beispiel.1passwordserviceaccounts.eu', url: 'https://beispiel.1password.eu' });
  assert.deepEqual(f.aufrufe[0].args, ['whoami', '--format', 'json']);
  await assert.rejects(opWhoami({ token: TOKEN, exec: fake(() => ({ stdout: '[]' })).exec }), /keine Kontoangabe/);
});

// S146 (access-read access: schneller und Register-Lücken): den Namen des Service Accounts nennt op whoami nicht.
test('opSelf: argv user get --me --format json, nur Name, Typ und Status; tokenartiger Name verdeckt', async () => {
  const f = fake(() => ({ stdout: JSON.stringify({ id: 'U1', name: 'armagnac-claude', email: 'x@beispiel.1passwordserviceaccounts.eu', type: 'SERVICE_ACCOUNT', state: 'ACTIVE', created_at: 'z' }) }));
  assert.deepEqual(await opSelf({ token: TOKEN, exec: f.exec }), { name: 'armagnac-claude', typ: 'SERVICE_ACCOUNT', status: 'ACTIVE' });
  assert.deepEqual(f.aufrufe[0].args, ['user', 'get', '--me', '--format', 'json']);
  const g = fake(() => ({ stdout: JSON.stringify({ name: `ops_${'X'.repeat(30)}`, type: 'SERVICE_ACCOUNT' }) }));
  assert.equal((await opSelf({ token: TOKEN, exec: g.exec })).name, '[Name nicht ausgegeben]');
  await assert.rejects(opSelf({ token: TOKEN, exec: fake(() => ({ stdout: '[]' })).exec }), /keine Kontoangabe/);
});
