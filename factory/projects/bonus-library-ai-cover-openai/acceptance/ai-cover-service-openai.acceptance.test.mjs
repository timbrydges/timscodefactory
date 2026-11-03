// Factory-owned acceptance tests for bonus-library-ai-cover-openai (replaces the ai-cover-service acceptance tests for the OpenAI response format). The builder must
// make these pass and cannot edit them. Contract: src/lib/ai-cover-service.ts exports
//   coverObjectPath(owner, item, id) -> `${owner}/${item}-ai-cover-${id.slice(0, 16)}.png`
//     (owner and item UUIDs, id 64 lowercase hex; throws otherwise).
//   coverGenerationEnabled(env) -> true only when VERCEL_ENV is "production",
//     VERCEL_GIT_COMMIT_SHA is 40 lowercase hex and BONUS_AI_COVER_ACTIVATION_SHA equals it.
//   generateCover({ owner, item, title, style }, backend, enabled) where backend has
//     load(id), availability(), reserve(id, owner, item, style, request),
//     invoke(body: string) -> parsed JSON, store(owner, item, id, bytes) -> object path,
//     finish(id, objectPath, sha256). Order: load first and return any saved record
//     unchanged (never invoke twice for one id, including a "reserved" record whose outcome
//     is unknown); then throw unless enabled and availability().enabled; build the request
//     with buildCoverRequest (throw if null); reserve; invoke JSON.stringify(request) once;
//     parseCoverResponse (throw if null, attempt stays consumed); store; finish with the
//     lowercase hex SHA-256 of the bytes; return
//     { status: "generated", style, object_path, sha256 }.
//   coverRequest(request, { authorize, backend, env }) HTTP handler. authorize(item) returns
//     { owner, title } or null. Every reply has Cache-Control "private, no-store".
//     GET ?item=<uuid>&style=<style>: 400 if invalid; 403 if not authorized; when
//     env.BONUS_AI_COVER_ROLE_ARN is unset or VERCEL_ENV is not production:
//     { enabled: false, reason: "paused", saved: null }; a saved record:
//     { enabled: false, reason: "saved", saved }; otherwise paused unless
//     coverGenerationEnabled(env), else { ...availability, saved: null }.
//     POST: 405 for other methods; 403 unless Origin is https://bonus-library.vercel.app;
//     JSON body exactly { item_id, style } else 400; 403 if not authorized; 409 when not
//     configured; otherwise { saved: await generateCover(...) }; any failure 409 with a
//     fixed message that never includes error text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { coverGenerationId } from '../../src/lib/ai-cover-budget.ts';
import { coverGenerationEnabled, coverObjectPath, coverRequest, generateCover } from '../../src/lib/ai-cover-service.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
const ITEM = '22222222-2222-4222-8222-222222222222';
const COMMIT = 'c'.repeat(40);
const ENV = { VERCEL_ENV: 'production', VERCEL_GIT_COMMIT_SHA: COMMIT, BONUS_AI_COVER_ACTIVATION_SHA: COMMIT,
  BONUS_AI_COVER_ROLE_ARN: 'arn:aws:iam::666730517561:role/example' };
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);
const IMAGE = { data: [{ b64_json: Buffer.from(PNG).toString('base64') }] };

function backend({ saved = null, ready = true, response = IMAGE } = {}) {
  const calls = [];
  return { calls,
    async load(id) { calls.push(['load', id]); return saved; },
    async availability() { calls.push(['availability']); return { enabled: ready, reason: ready ? 'ready' : 'limit' }; },
    async reserve(...args) { calls.push(['reserve', ...args]); },
    async invoke(body) { calls.push(['invoke', body]); return response; },
    async store(owner, item, id, bytes) { calls.push(['store', owner, item, id, bytes.length]); return coverObjectPath(owner, item, id); },
    async finish(...args) { calls.push(['finish', ...args]); } };
}

test('object path and activation gate', () => {
  const id = coverGenerationId(OWNER, ITEM, 'ebook');
  assert.equal(coverObjectPath(OWNER, ITEM, id), `${OWNER}/${ITEM}-ai-cover-${id.slice(0, 16)}.png`);
  assert.throws(() => coverObjectPath('x', ITEM, id));
  assert.throws(() => coverObjectPath(OWNER, ITEM, 'abc'));
  assert.equal(coverGenerationEnabled(ENV), true);
  for (const change of [{ VERCEL_ENV: 'preview' }, { BONUS_AI_COVER_ACTIVATION_SHA: 'd'.repeat(40) },
    { VERCEL_GIT_COMMIT_SHA: 'main', BONUS_AI_COVER_ACTIVATION_SHA: 'main' }, { BONUS_AI_COVER_ACTIVATION_SHA: undefined }]) {
    assert.equal(coverGenerationEnabled({ ...ENV, ...change }), false, JSON.stringify(change));
  }
});

test('generates once: reserve, one invocation, store, finish', async () => {
  const fake = backend();
  const id = coverGenerationId(OWNER, ITEM, 'software_box');
  const saved = await generateCover({ owner: OWNER, item: ITEM, title: 'Dragon Atlas', style: 'software_box' }, fake, true);
  const sha = createHash('sha256').update(PNG).digest('hex');
  const path = coverObjectPath(OWNER, ITEM, id);
  assert.deepEqual(saved, { status: 'generated', style: 'software_box', object_path: path, sha256: sha });
  assert.deepEqual(fake.calls.map(c => c[0]), ['load', 'availability', 'reserve', 'invoke', 'store', 'finish']);
  assert.equal(fake.calls[0][1], id);
  const reserve = fake.calls[2];
  assert.deepEqual(reserve.slice(1, 5), [id, OWNER, ITEM, 'software_box']);
  assert.equal(reserve[5].size, '1024x1024');
  assert.deepEqual(JSON.parse(fake.calls[3][1]), reserve[5]);
  assert.deepEqual(fake.calls[5].slice(1), [id, path, sha]);
});

test('a saved or unknown-outcome record is returned without another paid call', async () => {
  for (const saved of [{ status: 'reserved', style: 'ebook' },
    { status: 'generated', style: 'ebook', object_path: 'x', sha256: 'y' }]) {
    const fake = backend({ saved });
    assert.deepEqual(await generateCover({ owner: OWNER, item: ITEM, title: 'Atlas', style: 'ebook' }, fake, true), saved);
    assert.deepEqual(fake.calls.map(c => c[0]), ['load']);
  }
});

test('disabled, unavailable, invalid title or invalid image never store a cover', async () => {
  const cases = [[backend(), false, 'Atlas'], [backend({ ready: false }), true, 'Atlas'], [backend(), true, '   '],
    [backend({ response: { data: [{ b64_json: 'bm90IGEgcG5n' }] } }), true, 'Atlas']];
  for (const [fake, enabled, title] of cases) {
    await assert.rejects(generateCover({ owner: OWNER, item: ITEM, title, style: 'ebook' }, fake, enabled));
    assert.ok(!fake.calls.some(c => c[0] === 'store' || c[0] === 'finish'));
    assert.ok(fake.calls.filter(c => c[0] === 'invoke').length <= 1);
  }
});

const ORIGIN = 'https://bonus-library.vercel.app';
const authorize = async (item) => item === ITEM ? { owner: OWNER, title: 'Dragon Atlas' } : null;
const get = (query) => new Request(`${ORIGIN}/api/cover?${query}`);
const post = (body, origin = ORIGIN) => new Request(`${ORIGIN}/api/cover`, { method: 'POST',
  headers: { 'content-type': 'application/json', origin }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('GET reports saved, paused or availability', async () => {
  let response = await coverRequest(get(`item=${ITEM}&style=ebook`), { authorize, backend: () => backend(), env: ENV });
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(await response.json(), { enabled: true, reason: 'ready', saved: null });
  response = await coverRequest(get(`item=${ITEM}&style=ebook`), { authorize, backend: () => backend({ ready: false }), env: ENV });
  assert.deepEqual(await response.json(), { enabled: false, reason: 'limit', saved: null });
  const saved = { status: 'generated', style: 'ebook', object_path: 'p', sha256: 's' };
  response = await coverRequest(get(`item=${ITEM}&style=ebook`), { authorize, backend: () => backend({ saved }), env: { ...ENV, BONUS_AI_COVER_ACTIVATION_SHA: undefined } });
  assert.deepEqual(await response.json(), { enabled: false, reason: 'saved', saved });
  response = await coverRequest(get(`item=${ITEM}&style=ebook`), { authorize, backend: () => backend(), env: { ...ENV, BONUS_AI_COVER_ACTIVATION_SHA: undefined } });
  assert.deepEqual(await response.json(), { enabled: false, reason: 'paused', saved: null });
  response = await coverRequest(get(`item=${ITEM}&style=ebook`), { authorize, backend: () => { throw new Error('no'); }, env: { ...ENV, BONUS_AI_COVER_ROLE_ARN: undefined } });
  assert.deepEqual(await response.json(), { enabled: false, reason: 'paused', saved: null });
  assert.equal((await coverRequest(get(`item=${ITEM}&style=poster`), { authorize, backend: () => backend(), env: ENV })).status, 400);
  assert.equal((await coverRequest(get('item=33333333-3333-4333-8333-333333333333&style=ebook'), { authorize, backend: () => backend(), env: ENV })).status, 403);
});

test('POST generates only for an authorized same-origin exact request', async () => {
  const fake = backend();
  let response = await coverRequest(post({ item_id: ITEM, style: 'ebook' }), { authorize, backend: () => fake, env: ENV });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).saved.status, 'generated');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  const deps = { authorize, backend: () => backend(), env: ENV };
  assert.equal((await coverRequest(post({ item_id: ITEM, style: 'ebook' }, 'https://evil.example'), deps)).status, 403);
  assert.equal((await coverRequest(post({ item_id: ITEM, style: 'ebook', extra: 1 }), deps)).status, 400);
  assert.equal((await coverRequest(post('not json'), deps)).status, 400);
  assert.equal((await coverRequest(post({ item_id: '33333333-3333-4333-8333-333333333333', style: 'ebook' }), deps)).status, 403);
  assert.equal((await coverRequest(post({ item_id: ITEM, style: 'ebook' }), { ...deps, env: { ...ENV, VERCEL_ENV: 'preview' } })).status, 409);
  assert.equal((await coverRequest(new Request(`${ORIGIN}/api/cover`, { method: 'DELETE' }), deps)).status, 405);
  response = await coverRequest(post({ item_id: ITEM, style: 'ebook' }), { authorize,
    backend: () => backend({ response: { secret: 'provider text' } }), env: ENV });
  assert.equal(response.status, 409);
  assert.ok(!(await response.text()).includes('provider text'));
});
