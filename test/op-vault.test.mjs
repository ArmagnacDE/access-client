// Tresornamen mit und ohne Präfix (src/op-vault.js), op gemockt; Präfix im Test „team-“.
import test from 'node:test';
import assert from 'node:assert/strict';
import { schreibweisen, tresorSuche, einEintrag, istKeinTresor, zerlegeVerweis, verweisMit, OpVaultError } from '../src/op-vault.js';

const KEIN = (n) => new Error(`"${n}" isn't a vault in this account. Specify the vault with its ID or name.`);
const mock = (vorhanden, aufrufe = []) => ({
  aufrufe,
  vaultGet: async (n) => {
    aufrufe.push(n);
    if (vorhanden.has(n.toLowerCase())) return { name: n };
    throw KEIN(n);
  },
});

test('schreibweisen: konfigurierte zuerst, dann mit bzw. ohne Präfix', () => {
  assert.deepEqual(schreibweisen('team-kasse', { prefix: 'team-' }), ['team-kasse', 'kasse']);
  assert.deepEqual(schreibweisen('kasse', { prefix: 'team-' }), ['kasse', 'team-kasse']);
  assert.deepEqual(schreibweisen('TEAM-Zoll', { prefix: 'team-' }), ['TEAM-Zoll', 'Zoll']);
  assert.deepEqual(schreibweisen('Zoll', { prefix: 'team-' }), ['Zoll', 'team-Zoll']);
  assert.throws(() => schreibweisen('', { prefix: 'team-' }), OpVaultError);
  assert.throws(() => schreibweisen('a/b', { prefix: 'team-' }), OpVaultError);
});

test('nur alte Schreibweise vorhanden: team-kasse, ein Eintrag', async () => {
  const m = mock(new Set(['team-kasse']));
  const s = tresorSuche({ ...m, prefix: 'team-' });
  assert.deepEqual(await s.tresore('team-kasse'), ['team-kasse']);
  assert.deepEqual(await s.tresore('kasse'), ['team-kasse'], 'umgekehrt konfiguriert findet die alte Schreibweise');
  const r = await einEintrag(s, 'team-kasse', async (v) => (v === 'team-kasse' ? 'id1' : null));
  assert.deepEqual(r, { vault: 'team-kasse', wert: 'id1' });
});

test('nach dem Umbenennen: Konfiguration team-kasse findet kasse', async () => {
  const m = mock(new Set(['kasse']));
  const s = tresorSuche({ ...m, prefix: 'team-' });
  assert.deepEqual(await s.tresore('team-kasse'), ['kasse']);
  const r = await einEintrag(s, 'team-kasse', async (v) => (v === 'kasse' ? 'id1' : null));
  assert.deepEqual(r, { vault: 'kasse', wert: 'id1' });
});

test('beide vorhanden: Eintrag nur in einem wird genommen, in beiden ist ein Stopp', async () => {
  const s = tresorSuche({ ...mock(new Set(['team-kasse', 'kasse'])), prefix: 'team-' });
  assert.deepEqual(await s.tresore('team-kasse'), ['team-kasse', 'kasse']);
  assert.deepEqual(await einEintrag(s, 'team-kasse', async (v) => (v === 'kasse' ? 'id2' : null)), { vault: 'kasse', wert: 'id2' });
  await assert.rejects(einEintrag(s, 'team-kasse', async () => 'idX'), /doppelt/);
});

test('keine Schreibweise vorhanden bzw. Eintrag fehlt', async () => {
  const s = tresorSuche({ ...mock(new Set(['team-kasse'])), prefix: 'team-' });
  assert.deepEqual(await einEintrag(s, 'team-reise', async () => 'x'), { vault: null, grund: 'kein-tresor' });
  assert.deepEqual(await einEintrag(s, 'team-kasse', async () => null), { vault: null, grund: 'fehlt' });
});

test('anderer Fehler (Token, Netz, Limit) ist ein Stopp, kein Ausweichen', async () => {
  const aufrufe = [];
  const s = tresorSuche({ prefix: 'team-', vaultGet: async (n) => { aufrufe.push(n); throw new Error('[ERROR] (429) Too Many Requests'); } });
  await assert.rejects(s.tresore('team-kasse'), /429/);
  assert.deepEqual(aufrufe, ['team-kasse'], 'zweite Schreibweise nicht versucht');
  const s2 = tresorSuche({ prefix: 'team-', vaultGet: async () => { throw new Error('authorization prompt dismissed / invalid token'); } });
  await assert.rejects(s2.tresore('kasse'), /token/);
});

test('je Lauf gemerkt: jede Schreibweise höchstens einmal abgefragt, auch bei gleichzeitigen Anfragen', async () => {
  const m = mock(new Set(['team-kasse']));
  const s = tresorSuche({ ...m, prefix: 'team-' });
  await Promise.all([s.tresore('team-kasse'), s.tresore('TEAM-KASSE'), s.tresore('team-kasse')]);
  await s.tresore('team-kasse');
  await s.tresore('kasse'); // beide Schreibweisen in einer Konfiguration: kein zweiter Abruf
  assert.deepEqual(m.aufrufe, ['team-kasse', 'kasse']);
});

test('klare Stopp-Lage, ganzes stderr, Namen mit Sonderzeichen', async () => {
  const s = tresorSuche({ prefix: 'team-', vaultGet: async (n) => { if (n === 'team-zoll') return {}; throw new Error('op vault get fehlgeschlagen: (429) Too Many Requests'); } });
  await assert.rejects(s.tresore('team-zoll'), /Gegenprobe auf die andere Schreibweise „zoll“ \(Tresor „team-zoll“ gefunden\).*429/);
  const s2 = tresorSuche({ prefix: 'team-', vaultGet: async (n) => { throw Object.assign(new Error('op vault get fehlgeschlagen: [WARNING] neue Version verfügbar'), { opStderr: `[WARNING] neue Version verfügbar\n[ERROR] "${n}" isn't a vault in this account.` }); } });
  assert.deepEqual(await s2.tresore('team-x'), [], 'Hinweiszeile vor der Meldung führt nicht zum Stopp');
  assert.deepEqual(schreibweisen('Zoll & Steuer', { prefix: 'team-' }), ['Zoll & Steuer', 'team-Zoll & Steuer']);
  assert.throws(() => schreibweisen(' x', { prefix: 'team-' }), OpVaultError);
  assert.throws(() => schreibweisen('a\nb', { prefix: 'team-' }), OpVaultError);
  assert.throws(() => schreibweisen('--help', { prefix: 'team-' }), OpVaultError, 'kein führendes „-“ (wäre eine op-Option)');
  assert.deepEqual(schreibweisen('team- x', { prefix: 'team-' }), ['team- x'], 'andere Schreibweise mit führendem Leerzeichen entfällt');
  const s3 = tresorSuche({ prefix: 'team-', vaultGet: async () => { throw new Error('(429)'); } });
  const fehler = await s3.tresore('team-y').catch((e) => e);
  assert.ok(!Object.keys(fehler).includes('cause') && fehler.cause instanceof Error, 'cause vorhanden, aber nicht aufzählbar');
});

test('Stopp-Fehler wird nicht gemerkt (nächster Versuch fragt neu)', async () => {
  let n = 0;
  const s = tresorSuche({ prefix: 'team-', vaultGet: async (v) => { n++; if (n === 1) throw new Error('network timeout'); if (v === 'team-x') return {}; throw KEIN(v); } });
  await assert.rejects(s.tresore('team-x'));
  assert.deepEqual(await s.tresore('team-x'), ['team-x']);
});

test('Wortlaut und op://-Verweise', () => {
  assert.ok(istKeinTresor('[ERROR] 2026/11/13 20:51:39 "kasse" isn\'t a vault in this account. Specify the vault with its ID or name.'));
  assert.ok(istKeinTresor('could not read secret \'op://kasse/x/y\': could not get item kasse/x: "kasse" isn\'t a vault in this account.'));
  assert.ok(!istKeinTresor('"x" isn\'t an item in the "team-kasse" vault'));
  assert.deepEqual(zerlegeVerweis('op://Zoll/ELSTER/password'), { vault: 'Zoll', rest: 'ELSTER/password' });
  assert.equal(verweisMit('op://team-zoll/ELSTER/password', 'customs'), 'op://customs/ELSTER/password');
  assert.throws(() => zerlegeVerweis('ELSTER/password'), OpVaultError);
});

test('ohne Präfix nur die konfigurierte Schreibweise; ungültiges Präfix ist ein Fehler', async () => {
  assert.deepEqual(schreibweisen('team-kasse'), ['team-kasse']);
  assert.deepEqual(schreibweisen('kasse', { prefix: '' }), ['kasse']);
  for (const prefix of ['team', '-', 'a/b-', 'x'.repeat(17) + '-', 5]) assert.throws(() => schreibweisen('kasse', { prefix }), OpVaultError, String(prefix));
  const aufrufe = [];
  const s = tresorSuche(mock(new Set(['kasse']), aufrufe));
  assert.deepEqual(await s.tresore('team-kasse'), []);
  assert.deepEqual(aufrufe, ['team-kasse'], 'ohne Präfix keine zweite Schreibweise');
});
