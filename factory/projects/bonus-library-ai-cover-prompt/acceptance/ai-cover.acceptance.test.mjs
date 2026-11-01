// Factory-owned acceptance tests for bonus-library-ai-cover-prompt. The builder must
// make these pass and cannot edit them. Contract: src/lib/ai-cover.ts exports
//   AI_COVER_MODEL ("stability.stable-image-core-v1:1"), AI_COVER_REGION ("us-west-2"),
//   AI_COVER_STYLES (["ebook", "software_box"]), AI_COVER_MAX_IMAGE_BYTES (5 MiB),
//   AI_COVER_STYLE_LABELS ({ ebook: "eBook cover", software_box: "Software box" })
//   buildCoverRequest(title, style): null for an invalid style or a title that is
//     empty after trimming, longer than 120 characters, or contains control characters;
//     otherwise { prompt, negative_prompt, aspect_ratio, output_format: "png" } where
//     aspect_ratio is "2:3" for ebook and "4:5" for software_box, the prompt names the
//     style and contains the trimmed title exactly once, and the prompt is at most 1000
//     characters. Double quotes in the title are replaced by single quotes.
//   parseCoverResponse(body): for a Stable Image Core response object
//     { images: [base64], finish_reasons: [null], seeds: [n] } returns
//     { bytes: Uint8Array, mediaType: "image/png" } only when there is exactly one image,
//     its finish reason is null, it decodes from strict base64 to a PNG signature and is
//     at most AI_COVER_MAX_IMAGE_BYTES; otherwise null.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AI_COVER_MAX_IMAGE_BYTES,
  AI_COVER_MODEL,
  AI_COVER_REGION,
  AI_COVER_STYLES,
  AI_COVER_STYLE_LABELS,
  buildCoverRequest,
  parseCoverResponse,
} from '../../src/lib/ai-cover.ts';

const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72, 68, 82]);
const b64 = (bytes) => Buffer.from(bytes).toString('base64');

test('pinned model, region, styles and limits', () => {
  assert.equal(AI_COVER_MODEL, 'stability.stable-image-core-v1:1');
  assert.equal(AI_COVER_REGION, 'us-west-2');
  assert.deepEqual([...AI_COVER_STYLES], ['ebook', 'software_box']);
  assert.deepEqual({ ...AI_COVER_STYLE_LABELS }, { ebook: 'eBook cover', software_box: 'Software box' });
  assert.equal(AI_COVER_MAX_IMAGE_BYTES, 5 * 1024 * 1024);
});

test('ebook and software box requests use the title and fixed formats', () => {
  const ebook = buildCoverRequest('  The Dragon Atlas  ', 'ebook');
  assert.equal(ebook.aspect_ratio, '2:3');
  assert.equal(ebook.output_format, 'png');
  assert.equal(ebook.prompt.split('The Dragon Atlas').length - 1, 1);
  assert.match(ebook.prompt, /ebook|e-book|book cover/i);
  assert.ok(ebook.prompt.length <= 1000);
  assert.equal(typeof ebook.negative_prompt, 'string');
  const box = buildCoverRequest('Pixel Studio Pro', 'software_box');
  assert.equal(box.aspect_ratio, '4:5');
  assert.match(box.prompt, /software/i);
  assert.match(box.prompt, /box/i);
  assert.equal(box.prompt.split('Pixel Studio Pro').length - 1, 1);
  assert.deepEqual(Object.keys(box).sort(), ['aspect_ratio', 'negative_prompt', 'output_format', 'prompt']);
});

test('quotes are neutralized and invalid titles or styles are rejected', () => {
  const quoted = buildCoverRequest('Say "Hello" World', 'ebook');
  assert.ok(!quoted.prompt.includes('"Hello"'));
  assert.ok(quoted.prompt.includes("Say 'Hello' World"));
  for (const [title, style] of [['', 'ebook'], ['   ', 'ebook'], ['x'.repeat(121), 'ebook'],
    ['bad\ntitle', 'ebook'], ['bad\u0000title', 'software_box'], ['Fine', 'poster'], ['Fine', undefined],
    [null, 'ebook']]) {
    assert.equal(buildCoverRequest(title, style), null, JSON.stringify([title, style]));
  }
  assert.notEqual(buildCoverRequest('x'.repeat(120), 'ebook'), null);
});

test('a single safe PNG response is accepted', () => {
  const result = parseCoverResponse({ images: [b64(PNG)], finish_reasons: [null], seeds: [42] });
  assert.equal(result.mediaType, 'image/png');
  assert.ok(result.bytes instanceof Uint8Array);
  assert.deepEqual([...result.bytes], [...PNG]);
});

test('filtered, malformed, oversized or non-PNG responses are rejected', () => {
  const jpeg = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]);
  const big = new Uint8Array(AI_COVER_MAX_IMAGE_BYTES + 1); big.set(PNG);
  for (const body of [
    null, {}, { images: [], finish_reasons: [] },
    { images: [b64(PNG), b64(PNG)], finish_reasons: [null, null] },
    { images: [b64(PNG)], finish_reasons: ['Filter reason: prompt'] },
    { images: [b64(jpeg)], finish_reasons: [null] },
    { images: ['not base64!!'], finish_reasons: [null] },
    { images: [b64(big)], finish_reasons: [null] },
    { images: [42], finish_reasons: [null] },
  ]) {
    assert.equal(parseCoverResponse(body), null, JSON.stringify(body)?.slice(0, 80));
  }
});
