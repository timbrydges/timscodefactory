// Factory-owned acceptance tests for bonus-library-ai-cover-openai. The builder must make
// these pass and cannot edit them. The owner chose OpenAI gpt-image-2 after a test
// (realistic 3D mockups with the exact title; about US$0.06 per image).
//   src/lib/ai-cover.ts exports AI_COVER_MODEL "gpt-image-2", AI_COVER_PROVIDER_URL
//     "https://api.openai.com/v1/images/generations", AI_COVER_PROMPT_VERSION 2,
//     AI_COVER_STYLES and AI_COVER_STYLE_LABELS (unchanged), AI_COVER_MAX_IMAGE_BYTES
//     8 MiB, and AI_COVER_REGION "us-west-2" (kept until the wiring task removes Bedrock).
//   buildCoverRequest(title, style) returns null for invalid input (as before) or exactly
//     { model, prompt, size, quality: "medium", n: 1 }: size "1024x1536" for ebook and
//     "1024x1024" for software_box. The prompt asks for a professional 3D product mockup
//     photo (a hardcover book standing upright, or a retail software box at a
//     three-quarter angle) on a clean light background, shows the trimmed title in double
//     quotes exactly once with double quotes in the title replaced by single quotes, says
//     "spelled exactly", and forbids people and other words. At most 1000 characters.
//   parseCoverResponse accepts exactly { data: [{ b64_json }] } (other fields allowed in
//     the item) holding strict base64 of a PNG of at most 8 MiB; otherwise null.
//   src/lib/ai-cover-budget.ts: AI_COVER_RESERVE_MICRO_USD 100_000; coverGenerationId also
//     hashes AI_COVER_PROMPT_VERSION (one fresh attempt per owner, item and style for the
//     new prompt); coverReservationTransaction accepts only a request equal in shape to
//     buildCoverRequest output for that style and records AI_COVER_MODEL.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { AI_COVER_MAX_IMAGE_BYTES, AI_COVER_MODEL, AI_COVER_PROMPT_VERSION, AI_COVER_PROVIDER_URL,
  AI_COVER_STYLE_LABELS, AI_COVER_STYLES, buildCoverRequest, parseCoverResponse } from '../../src/lib/ai-cover.ts';
import { AI_COVER_RESERVE_MICRO_USD, coverGenerationId, coverReservationTransaction } from '../../src/lib/ai-cover-budget.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
const ITEM = '22222222-2222-4222-8222-222222222222';
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

test('pinned OpenAI provider and limits', () => {
  assert.equal(AI_COVER_MODEL, 'gpt-image-2');
  assert.equal(AI_COVER_PROVIDER_URL, 'https://api.openai.com/v1/images/generations');
  assert.equal(AI_COVER_PROMPT_VERSION, 2);
  assert.equal(AI_COVER_MAX_IMAGE_BYTES, 8 * 1024 * 1024);
  assert.deepEqual([...AI_COVER_STYLES], ['ebook', 'software_box']);
  assert.deepEqual({ ...AI_COVER_STYLE_LABELS }, { ebook: 'eBook cover', software_box: 'Software box' });
  assert.equal(AI_COVER_RESERVE_MICRO_USD, 100_000);
});

test('mockup requests carry the exact title once', () => {
  const book = buildCoverRequest('  Streaming Profits Authority  ', 'ebook');
  assert.deepEqual(Object.keys(book).sort(), ['model', 'n', 'prompt', 'quality', 'size']);
  assert.deepEqual([book.model, book.size, book.quality, book.n], ['gpt-image-2', '1024x1536', 'medium', 1]);
  assert.match(book.prompt, /3D product mockup/i);
  assert.match(book.prompt, /hardcover book/i);
  assert.equal(book.prompt.split('"Streaming Profits Authority"').length - 1, 1);
  assert.match(book.prompt, /spelled exactly/i);
  assert.match(book.prompt, /no people/i);
  assert.match(book.prompt, /no other words/i);
  const box = buildCoverRequest('Pixel Studio Pro', 'software_box');
  assert.equal(box.size, '1024x1024');
  assert.match(box.prompt, /software box/i);
  assert.match(box.prompt, /three-quarter/i);
  assert.equal(box.prompt.split('"Pixel Studio Pro"').length - 1, 1);
  assert.ok(buildCoverRequest('Say "Hi"', 'ebook').prompt.includes(`"Say 'Hi'"`));
  for (const [title, style] of [['', 'ebook'], ['x'.repeat(121), 'ebook'], ['Atlas', 'poster'], ['A\u0007', 'ebook'], [5, 'ebook']]) {
    assert.equal(buildCoverRequest(title, style), null);
  }
  for (const style of AI_COVER_STYLES) {
    assert.ok(buildCoverRequest('x'.repeat(120), style).prompt.length <= 1000);
  }
});

test('only a single safe PNG in the OpenAI response is accepted', () => {
  const ok = parseCoverResponse({ data: [{ b64_json: Buffer.from(PNG).toString('base64'), revised_prompt: 'x' }], created: 1 });
  assert.deepEqual([...ok.bytes], [...PNG]);
  assert.equal(ok.mediaType, 'image/png');
  for (const body of [null, {}, { data: [] }, { data: [{}, {}] }, { data: [{ b64_json: 'bm90IGEgcG5n' }] },
    { data: [{ b64_json: 'not base64!' }] }, { data: [{ url: 'https://example.invalid/x.png' }] }]) {
    assert.equal(parseCoverResponse(body), null, JSON.stringify(body));
  }
});

test('the improved prompt gives one fresh attempt and reserves US$0.10', () => {
  const id = coverGenerationId(OWNER, ITEM, 'ebook');
  assert.notEqual(id, createHash('sha256').update(`${OWNER}\n${ITEM}\nebook`, 'utf8').digest('hex'));
  assert.equal(coverGenerationId(OWNER, ITEM, 'ebook'), id);
  const request = buildCoverRequest('Atlas', 'ebook');
  const tx = coverReservationTransaction(id, OWNER, ITEM, 'ebook', request, 1_800_000_000, 'a'.repeat(40));
  const [{ Update: update }, { Put: put }] = tx.TransactItems;
  assert.ok(JSON.stringify(update.ExpressionAttributeValues).includes('100000'));
  assert.ok(JSON.stringify(update.ExpressionAttributeValues).includes('1900000'));
  assert.deepEqual(put.Item.reserved_micro_usd, { N: '100000' });
  assert.deepEqual(put.Item.model, { S: 'gpt-image-2' });
  assert.deepEqual(JSON.parse(put.Item.request.S), request);
  for (const bad of [{ ...request, size: '1024x1024' }, { ...request, extra: 1 },
    { prompt: 'p', negative_prompt: 'n', aspect_ratio: '2:3', output_format: 'png' }]) {
    assert.throws(() => coverReservationTransaction(id, OWNER, ITEM, 'ebook', bad, 1_800_000_000, 'a'.repeat(40)));
  }
});
