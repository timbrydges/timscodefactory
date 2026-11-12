// Factory-owned acceptance tests for bonus-library-ai-cover-unique-path (replaces the ai-cover-backend-openai acceptance tests: each stored image gets a unique file name). The builder must
// make these pass and cannot edit them. Contract: src/lib/ai-cover-backend.ts exports
//   createCoverBackend(deps) returning the CoverBackend used by generateCover in
//   ai-cover-service.ts. deps (all injected; the module imports no SDK):
//     getItem(input) -> { Item?: DynamoDB attribute map }
//     updateItem(input), transactWrite(input)
//     invokeModel({ modelId, contentType, accept, body }) -> Uint8Array response body
//     upload(path, bytes, contentType)
//     now() -> Unix seconds; commit (40 lowercase hex, else createCoverBackend throws)
//   Records live in AI_COVER_TABLE under PK AI_COVER_PARTITION; attempts use SK
//   "APP#<id>", the budget uses SK "BUDGET"; every read is ConsistentRead.
//   load(id): null when absent, else { status, style } plus object_path and sha256 when
//     stored.
//   availability(): coverBudgetAvailability of the BUDGET record (N -> number,
//     BOOL -> boolean, S -> string; null when absent) at now() for commit.
//   reserve(...): transactWrite(coverReservationTransaction(..., now(), commit)).
//   invoke(body): one invokeModel with modelId AI_COVER_MODEL and JSON content types;
//     the response must be at most 8 MiB of strict UTF-8 JSON (throws otherwise).
//   store(owner, item, id, bytes): upload to coverObjectPath(owner, item, id) with "-<now()>"
//     inserted before ".png" (so a cleared attempt never collides with an earlier file;
//     private storage refuses overwrites), content type "image/png", and return that path.
//   finish(id, path, sha256): updateItem setting status "generated", object_path and
//     sha256 on APP#<id> only while its status is "reserved".
import test from 'node:test';
import assert from 'node:assert/strict';
import { AI_COVER_MODEL, buildCoverRequest } from '../../src/lib/ai-cover.ts';
import { AI_COVER_PARTITION, AI_COVER_TABLE, coverGenerationId } from '../../src/lib/ai-cover-budget.ts';
import { coverObjectPath } from '../../src/lib/ai-cover-service.ts';
import { createCoverBackend } from '../../src/lib/ai-cover-backend.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
const ITEM = '22222222-2222-4222-8222-222222222222';
const COMMIT = 'a'.repeat(40);
const NOW = 1_800_000_000;
const ID = coverGenerationId(OWNER, ITEM, 'ebook');
const budget = { app_enabled: { BOOL: true }, app_version: { S: 'bonus-ai-cover-app-v1' }, app_commit: { S: COMMIT },
  limit_micro_usd: { N: '2000000' }, reserved_micro_usd: { N: '0' }, dispatches: { N: '0' },
  app_dispatch_limit: { N: '40' }, app_expires_at: { N: String(NOW + 60) } };

function fake(items = {}, response = new TextEncoder().encode('{"images":["x"]}')) {
  const calls = [];
  const deps = { commit: COMMIT, now: () => NOW,
    async getItem(input) { calls.push(['getItem', input]); return { Item: items[input.Key.SK.S] }; },
    async updateItem(input) { calls.push(['updateItem', input]); return {}; },
    async transactWrite(input) { calls.push(['transactWrite', input]); return {}; },
    async invokeModel(input) { calls.push(['invokeModel', input]); return response; },
    async upload(...args) { calls.push(['upload', ...args]); } };
  return { calls, backend: createCoverBackend(deps) };
}

test('requires an exact commit', () => {
  assert.throws(() => createCoverBackend({ ...fake().backend, commit: 'main', now: () => NOW }));
});

test('load reads one consistent attempt record', async () => {
  let { calls, backend } = fake();
  assert.equal(await backend.load(ID), null);
  assert.deepEqual(calls[0][1], { TableName: AI_COVER_TABLE, ConsistentRead: true,
    Key: { PK: { S: AI_COVER_PARTITION }, SK: { S: `APP#${ID}` } } });
  ({ backend } = fake({ [`APP#${ID}`]: { status: { S: 'reserved' }, style: { S: 'ebook' } } }));
  assert.deepEqual(await backend.load(ID), { status: 'reserved', style: 'ebook' });
  ({ backend } = fake({ [`APP#${ID}`]: { status: { S: 'generated' }, style: { S: 'ebook' },
    object_path: { S: 'p.png' }, sha256: { S: 'f'.repeat(64) } } }));
  assert.deepEqual(await backend.load(ID), { status: 'generated', style: 'ebook', object_path: 'p.png', sha256: 'f'.repeat(64) });
});

test('availability converts the budget record', async () => {
  let { calls, backend } = fake({ BUDGET: budget });
  assert.deepEqual(await backend.availability(), { enabled: true, reason: 'ready' });
  assert.deepEqual(calls[0][1].Key, { PK: { S: AI_COVER_PARTITION }, SK: { S: 'BUDGET' } });
  assert.equal(calls[0][1].ConsistentRead, true);
  ({ backend } = fake({ BUDGET: { ...budget, app_expires_at: { N: String(NOW) } } }));
  assert.deepEqual(await backend.availability(), { enabled: false, reason: 'expired' });
  ({ backend } = fake());
  assert.deepEqual(await backend.availability(), { enabled: false, reason: 'paused' });
});

test('reserve, invoke, store and finish use the fixed records and model', async () => {
  const { calls, backend } = fake();
  const request = buildCoverRequest('Atlas', 'ebook');
  await backend.reserve(ID, OWNER, ITEM, 'ebook', request);
  const tx = calls[0][1];
  assert.equal(tx.TransactItems.length, 2);
  assert.ok(JSON.stringify(tx).includes(String(NOW)) && JSON.stringify(tx).includes(COMMIT));
  assert.deepEqual(await backend.invoke('{"prompt":"p"}'), { images: ['x'] });
  assert.deepEqual(calls[1][1], { modelId: AI_COVER_MODEL, contentType: 'application/json',
    accept: 'application/json', body: '{"prompt":"p"}' });
  const bytes = Uint8Array.from([1, 2, 3]);
  const path = await backend.store(OWNER, ITEM, ID, bytes);
  assert.equal(path, coverObjectPath(OWNER, ITEM, ID).replace(/\.png$/, `-${NOW}.png`));
  assert.deepEqual(calls[2], ['upload', path, bytes, 'image/png']);
  await backend.finish(ID, path, 'e'.repeat(64));
  const update = calls[3][1];
  assert.equal(update.TableName, AI_COVER_TABLE);
  assert.deepEqual(update.Key, { PK: { S: AI_COVER_PARTITION }, SK: { S: `APP#${ID}` } });
  const text = JSON.stringify(update);
  for (const value of ['generated', 'reserved', path, 'e'.repeat(64), 'object_path', 'sha256']) assert.ok(text.includes(value), value);
  assert.match(update.ConditionExpression, /=/);
});

test('oversized or invalid model responses are rejected', async () => {
  await assert.rejects(fake({}, new TextEncoder().encode(`{"a":"${'x'.repeat(8 * 1024 * 1024)}"}`)).backend.invoke('{}'));
  await assert.rejects(fake({}, Uint8Array.from([0xff, 0xfe])).backend.invoke('{}'));
  await assert.rejects(fake({}, new TextEncoder().encode('not json')).backend.invoke('{}'));
});
