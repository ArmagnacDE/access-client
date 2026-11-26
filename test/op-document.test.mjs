// S40 (Google-Schlüssel ohne Datei): opDocumentGet (src/op-read.js) mit Fake-exec: kein echtes op, kein Netz.
import test from 'node:test';
import assert from 'node:assert/strict';
import { opDocumentGet, OpReadError, OpItemMissingError } from '../src/op-read.js';

const TOKEN = 'ops_' + 'B'.repeat(40);
const INHALT = '{"type":"service_account","private_key":"erfunden-nicht-echt"}';

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

test('opDocumentGet: argv document get <eintrag> --vault <tresor>, Umgebung genau PATH/HOME/Token, Buffer roh', async () => {
  const f = fake(() => ({ stdout: INHALT }));
  const wert = await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: f.exec, path: '/x/bin', home: '/home/test' });
  assert.ok(Buffer.isBuffer(wert));
  assert.equal(wert.toString(), INHALT);
  assert.equal(f.aufrufe.length, 1);
  const { cmd, args, opts } = f.aufrufe[0];
  assert.equal(cmd, 'op');
  assert.deepEqual(args, ['document', 'get', 'sa-jobs', '--vault', 'team-office']);
  assert.deepEqual(opts.env, { PATH: '/x/bin', HOME: '/home/test', OP_SERVICE_ACCOUNT_TOKEN: TOKEN });
  assert.equal(opts.encoding, 'buffer');
  assert.ok(!args.some((x) => x.includes(TOKEN)));
});

test('opDocumentGet: Bytes unverändert, auch Nicht-UTF-8 und Zeilenenden (Codex S40 B1)', async () => {
  const roh = Buffer.from([0x7b, 0x00, 0x80, 0xff, 0x0d, 0x0a, 0x7d, 0x0a]);
  const exec = (cmd, args, opts, cb) => queueMicrotask(() => cb(null, Buffer.from(roh), Buffer.alloc(0)));
  const wert = await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec });
  assert.ok(wert.equals(roh));
});

test('opDocumentGet: ungültige Namen und Token → Abbruch vor op, ohne Wert in der Meldung', async () => {
  const f = fake(() => ({ stdout: INHALT }));
  const falsch = [
    { vault: 'team-office', item: '--out-file=/tmp/x' },
    { vault: 'team-office', item: 'a\nb' },
    { vault: 'team-office', item: TOKEN },
    { vault: '', item: 'sa-jobs' },
  ];
  for (const o of falsch) {
    await assert.rejects(opDocumentGet({ ...o, token: TOKEN, exec: f.exec }), (e) => e instanceof OpReadError && !e.message.includes(TOKEN), JSON.stringify(o));
  }
  await assert.rejects(opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: 'kein-token', exec: f.exec }), OpReadError);
  assert.equal(f.aufrufe.length, 0);
});

// Annahme (reviewer S40 #6): op document get meldet „isn't an item“ / „isn't a vault“ wie op item get (gemeinsamer
// Eintrags-Lookup der CLI); am echten op nicht belegt. Weicht der Wortlaut ab, wird es OpReadError (Stopp, nicht Fehlt).
test('opDocumentGet: Eintrag fehlt → OpItemMissingError; stdout nie in der Meldung; leer → Fehler', async () => {
  const fehlt = fake(() => ({ err: fehler(), stdout: INHALT, stderr: '[ERROR] 2026/11/26 10:00:00 "sa-jobs" isn\'t an item in the "team-office" vault. Specify the item with its UUID, name, or domain.\n' }));
  const e = await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: fehlt.exec }).catch((x) => x);
  assert.ok(e instanceof OpItemMissingError);
  assert.equal(e.was, 'eintrag');
  assert.ok(!e.message.includes('erfunden-nicht-echt'));

  const tresor = fake(() => ({ err: fehler(), stderr: '[ERROR] 2026/11/26 10:00:00 "team-office" isn\'t a vault in this account. Specify the vault with its ID or name.\n' }));
  const e2 = await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: tresor.exec }).catch((x) => x);
  assert.ok(e2 instanceof OpItemMissingError);
  assert.equal(e2.was, 'tresor');

  const leer = fake(() => ({ stdout: '' }));
  await assert.rejects(opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: leer.exec }), /leer/);
});

test('opDocumentGet: Ausgabelimit über maxBytes an execFile (Standard 1 MiB)', async () => {
  const f = fake(() => ({ stdout: INHALT }));
  await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: f.exec });
  assert.equal(f.aufrufe[0].opts.maxBuffer, 1024 * 1024);
  await opDocumentGet({ vault: 'team-office', item: 'sa-jobs', token: TOKEN, exec: f.exec, maxBytes: 4096 });
  assert.equal(f.aufrufe[1].opts.maxBuffer, 4096);
});
