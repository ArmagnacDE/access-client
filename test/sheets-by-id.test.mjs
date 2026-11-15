// src/sheets.js batchGetBySheetIds: Antwort nach sheetId zuordnen,
// sheetId 0 fehlt in der echten Antwort (gridRange: {}). Ohne Netz.
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.GOOGLE_OAUTH_CLIENT_ID = 'cid';
process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'csec';
process.env.GOOGLE_OAUTH_REFRESH_TOKEN = 'rt';
delete process.env.GOOGLE_SERVICE_ACCOUNT_FILE;
let antwort;
const calls = [];
globalThis.fetch = async (url, o = {}) => {
  if (String(url).startsWith('https://oauth2.googleapis.com/token')) return { ok: true, json: async () => ({ access_token: 'AT', expires_in: 3600 }) };
  calls.push({ url: String(url), method: o.method, body: o.body });
  return { ok: antwort.ok ?? true, status: antwort.status ?? 200, json: async () => antwort.json };
};
const { batchGetBySheetIds } = await import('../src/sheets.js');

test('batchGetBySheetIds: POST mit dataFilters, Zuordnung über die zurückgegebene sheetId (0 fehlt in der Antwort)', async () => {
  antwort = { json: { valueRanges: [
    { valueRange: { values: [['b']] }, dataFilters: [{ gridRange: { sheetId: 42 } }] },
    { valueRange: { values: [['a']] }, dataFilters: [{ gridRange: {} }] },
    { valueRange: {}, dataFilters: [{ gridRange: { sheetId: 7 } }] },
  ] } };
  const m = await batchGetBySheetIds('S', [0, 42, 7], { unformatted: true });
  assert.deepEqual([...m.entries()], [[42, [['b']]], [0, [['a']]], [7, []]]);
  assert.equal(calls[0].method, 'POST');
  assert.match(calls[0].url, /\/S\/values:batchGetByDataFilter$/);
  assert.deepEqual(JSON.parse(calls[0].body), { dataFilters: [{ gridRange: { sheetId: 0 } }, { gridRange: { sheetId: 42 } }, { gridRange: { sheetId: 7 } }], valueRenderOption: 'UNFORMATTED_VALUE' });
});

test('batchGetBySheetIds: Antwort ohne gridRange → Fehler; API-Fehler → Fehler; leere Liste ohne Request', async () => {
  antwort = { json: { valueRanges: [{ valueRange: { values: [] }, dataFilters: [{ a1Range: 'X' }] }] } };
  await assert.rejects(batchGetBySheetIds('S', [1]), /ohne eindeutige sheetId/);
  antwort = { ok: false, status: 429, json: { error: { code: 429 } } };
  await assert.rejects(batchGetBySheetIds('S', [1]), /Sheets API 429/);
  calls.length = 0;
  assert.equal((await batchGetBySheetIds('S', [])).size, 0);
  assert.equal(calls.length, 0);
});
