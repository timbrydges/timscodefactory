// Factory-owned acceptance tests for bonus-library-ai-cover-budget. The builder must
// make these pass and cannot edit them. Contract: src/lib/ai-cover-budget.ts exports
//   AI_COVER_TABLE ("tims-software-factory-state"), AI_COVER_PARTITION
//   ("BONUS_LIBRARY#AI_COVER#20261101"), AI_COVER_APP_VERSION ("bonus-ai-cover-app-v1"),
//   AI_COVER_LIMIT_MICRO_USD (2_000_000), AI_COVER_RESERVE_MICRO_USD (50_000),
//   AI_COVER_MAX_DISPATCHES (40)
//   coverGenerationId(owner, item, style): 64 lowercase hex characters, deterministic
//     for (owner UUID, item UUID, style in ai-cover AI_COVER_STYLES); throws otherwise.
//   coverBudgetAvailability(budget, now, commit) -> { enabled, reason } where reason is
//     "ready", "paused", "expired" or "limit". "paused" unless budget.app_enabled === true,
//     app_version equals AI_COVER_APP_VERSION, app_commit equals commit (40 hex),
//     limit_micro_usd equals AI_COVER_LIMIT_MICRO_USD, reserved_micro_usd and dispatches
//     are non-negative safe integers, app_dispatch_limit is an integer from 1 to
//     AI_COVER_MAX_DISPATCHES and app_expires_at is a safe integer. "expired" when
//     app_expires_at <= now; "limit" when dispatches >= app_dispatch_limit or another
//     reservation would exceed the limit.
//   coverReservationTransaction(id, owner, item, style, request, now, commit): a DynamoDB
//     TransactWriteItems input with exactly two items: an Update of the BUDGET row that
//     ADDs AI_COVER_RESERVE_MICRO_USD and one dispatch under a condition enforcing all of
//     the availability rules, and a Put of SK "APP#<id>" with attribute_not_exists(PK),
//     status "reserved", the style, the JSON request, the model and the reservation.
//     Throws for an invalid id, commit, time or request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCoverRequest, AI_COVER_MODEL } from '../../src/lib/ai-cover.ts';
import {
  AI_COVER_APP_VERSION,
  AI_COVER_LIMIT_MICRO_USD,
  AI_COVER_MAX_DISPATCHES,
  AI_COVER_PARTITION,
  AI_COVER_RESERVE_MICRO_USD,
  AI_COVER_TABLE,
  coverBudgetAvailability,
  coverGenerationId,
  coverReservationTransaction,
} from '../../src/lib/ai-cover-budget.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
const ITEM = '22222222-2222-4222-8222-222222222222';
const COMMIT = 'a'.repeat(40);
const NOW = 1_800_000_000;
const ready = { app_enabled: true, app_version: 'bonus-ai-cover-app-v1', app_commit: COMMIT,
  limit_micro_usd: 2_000_000, reserved_micro_usd: 0, dispatches: 0, app_dispatch_limit: 40,
  app_expires_at: NOW + 3600 };

test('fixed budget constants', () => {
  assert.equal(AI_COVER_TABLE, 'tims-software-factory-state');
  assert.equal(AI_COVER_PARTITION, 'BONUS_LIBRARY#AI_COVER#20261101');
  assert.equal(AI_COVER_APP_VERSION, 'bonus-ai-cover-app-v1');
  assert.equal(AI_COVER_LIMIT_MICRO_USD, 2_000_000);
  assert.equal(AI_COVER_RESERVE_MICRO_USD, 50_000);
  assert.equal(AI_COVER_MAX_DISPATCHES, 40);
});

test('one deterministic attempt per owner, item and style', () => {
  const ebook = coverGenerationId(OWNER, ITEM, 'ebook');
  assert.match(ebook, /^[0-9a-f]{64}$/);
  assert.equal(coverGenerationId(OWNER, ITEM, 'ebook'), ebook);
  assert.notEqual(coverGenerationId(OWNER, ITEM, 'software_box'), ebook);
  assert.notEqual(coverGenerationId(ITEM, OWNER, 'ebook'), ebook);
  for (const args of [['owner', ITEM, 'ebook'], [OWNER, 'item', 'ebook'], [OWNER, ITEM, 'poster']]) {
    assert.throws(() => coverGenerationId(...args));
  }
});

test('availability is ready only for an exact, enabled, unexpired budget', () => {
  assert.deepEqual(coverBudgetAvailability(ready, NOW, COMMIT), { enabled: true, reason: 'ready' });
  for (const change of [{ app_enabled: false }, { app_version: 'other' }, { app_commit: 'b'.repeat(40) },
    { limit_micro_usd: 5_000_000 }, { reserved_micro_usd: -1 }, { dispatches: 1.5 },
    { app_dispatch_limit: 0 }, { app_dispatch_limit: 41 }, { app_expires_at: 'soon' }]) {
    assert.deepEqual(coverBudgetAvailability({ ...ready, ...change }, NOW, COMMIT),
      { enabled: false, reason: 'paused' }, JSON.stringify(change));
  }
  assert.deepEqual(coverBudgetAvailability(null, NOW, COMMIT), { enabled: false, reason: 'paused' });
  assert.deepEqual(coverBudgetAvailability({ ...ready, app_expires_at: NOW }, NOW, COMMIT),
    { enabled: false, reason: 'expired' });
  assert.deepEqual(coverBudgetAvailability({ ...ready, dispatches: 40 }, NOW, COMMIT),
    { enabled: false, reason: 'limit' });
  assert.deepEqual(coverBudgetAvailability({ ...ready, reserved_micro_usd: 1_950_001 }, NOW, COMMIT),
    { enabled: false, reason: 'limit' });
  assert.deepEqual(coverBudgetAvailability({ ...ready, reserved_micro_usd: 1_950_000 }, NOW, COMMIT),
    { enabled: true, reason: 'ready' });
});

test('reservation is one atomic, conditional budget update plus an exclusive attempt record', () => {
  const id = coverGenerationId(OWNER, ITEM, 'ebook');
  const request = buildCoverRequest('The Dragon Atlas', 'ebook');
  const tx = coverReservationTransaction(id, OWNER, ITEM, 'ebook', request, NOW, COMMIT);
  assert.equal(tx.TransactItems.length, 2);
  const [{ Update: update }, { Put: put }] = tx.TransactItems;
  assert.equal(update.TableName, AI_COVER_TABLE);
  assert.deepEqual(update.Key, { PK: { S: AI_COVER_PARTITION }, SK: { S: 'BUDGET' } });
  assert.match(update.UpdateExpression, /ADD/);
  assert.match(update.UpdateExpression, /reserved_micro_usd/);
  assert.match(update.UpdateExpression, /dispatches/);
  const condition = update.ConditionExpression;
  for (const term of ['app_enabled', 'app_version', 'app_commit', 'limit_micro_usd', 'reserved_micro_usd',
    'dispatches', 'app_dispatch_limit', 'app_expires_at']) assert.ok(condition.includes(term), term);
  assert.match(condition, /dispatches\s*<\s*app_dispatch_limit/);
  assert.match(condition, /app_expires_at\s*>\s*:/);
  const values = JSON.stringify(update.ExpressionAttributeValues);
  for (const value of ['50000', 'bonus-ai-cover-app-v1', COMMIT, '2000000', '1950000', String(NOW)]) {
    assert.ok(values.includes(value), value);
  }
  assert.equal(put.TableName, AI_COVER_TABLE);
  assert.equal(put.ConditionExpression, 'attribute_not_exists(PK)');
  assert.deepEqual(put.Item.PK, { S: AI_COVER_PARTITION });
  assert.deepEqual(put.Item.SK, { S: `APP#${id}` });
  assert.deepEqual(put.Item.status, { S: 'reserved' });
  assert.deepEqual(put.Item.style, { S: 'ebook' });
  assert.deepEqual(JSON.parse(put.Item.request.S), request);
  assert.deepEqual(put.Item.model, { S: AI_COVER_MODEL });
  assert.deepEqual(put.Item.reserved_micro_usd, { N: '50000' });
});

test('invalid reservation inputs throw', () => {
  const id = coverGenerationId(OWNER, ITEM, 'ebook');
  const request = buildCoverRequest('Atlas', 'ebook');
  for (const args of [
    ['x', OWNER, ITEM, 'ebook', request, NOW, COMMIT],
    [id, OWNER, ITEM, 'ebook', request, NOW, 'main'],
    [id, OWNER, ITEM, 'ebook', request, -1, COMMIT],
    [id, OWNER, ITEM, 'ebook', null, NOW, COMMIT],
    [id, OWNER, ITEM, 'software_box', request, NOW, COMMIT],
  ]) assert.throws(() => coverReservationTransaction(...args));
});
