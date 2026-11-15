import { test } from 'node:test';
import assert from 'node:assert/strict';

test('Export read/google: nur lesende Funktionen, über den Paketnamen erreichbar', async () => {
  const m = await import('access-client/read/google');
  for (const f of ['driveQuery', 'driveInfo', 'driveDownload', 'sheetTabs', 'sheetValues', 'idFrom', 'nameQuery', 'folderQuery']) {
    assert.equal(typeof m[f], 'function', f);
  }
  const schreibend = Object.keys(m).filter((k) => /upload|create|update|delete|trash|move|copy|append|batchUpdate|permission/i.test(k));
  assert.deepEqual(schreibend, []);
});
