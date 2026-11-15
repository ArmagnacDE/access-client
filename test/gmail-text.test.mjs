// messageText meldet, wenn ein Teil schon beim Dekodieren gekürzt wurde (über PART_MAX).
import test from 'node:test';
import assert from 'node:assert/strict';
import { messageText, PART_MAX } from '../src/gmail.js';

test('truncated bei langem Teil, sonst false', () => {
  const kurz = { payload: { mimeType: 'text/plain', body: { data: Buffer.from('Hallo').toString('base64url') } } };
  assert.equal(messageText(kurz).truncated, false);
  const lang = { payload: { mimeType: 'text/plain', body: { data: Buffer.from('x'.repeat(PART_MAX + 1000)).toString('base64url') } } };
  const r = messageText(lang);
  assert.equal(r.truncated, true);
  assert.ok(r.text.length <= PART_MAX + 3);
});
