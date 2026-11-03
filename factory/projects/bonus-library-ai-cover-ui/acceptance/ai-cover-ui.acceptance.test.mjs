// Factory-owned acceptance tests for bonus-library-ai-cover-ui. The builder must make
// these pass and cannot edit them. React components cannot run under Node tests, so
// tsc, eslint and the independent reviewer check behaviour; these tests pin the
// required interface in the source.
//   src/app/dashboard/ai-cover-generator.tsx: a "use client" component exported as
//     AiCoverGenerator({ id, disabled, onUse }) where onUse(objectPath) returns a Promise.
//     A <select> lists every AI_COVER_STYLES value labelled with AI_COVER_STYLE_LABELS
//     (from @/lib/ai-cover). A "Generate AI cover" button first GETs
//     /api/cover?item=<id>&style=<style> (cache: "no-store"); a saved result is shown
//     without a POST; when enabled it POSTs JSON { item_id, style } to /api/cover. A
//     generated result is previewed by downloading object_path from the private
//     "bonus-generated" bucket with the browser Supabase client. A "Use this image" button
//     calls onUse(object_path). Paused, expired, limit and error states show a message.
//   src/app/dashboard/draft-review.tsx renders AiCoverGenerator for editable drafts and
//     implements onUse by updating library_items.cover_object_path and metadata_sha256
//     (the version 2 hash over sourceSha256, the saved title and description and the new
//     coverObjectPath) for this id, owner_id and status "draft", then refreshing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const ui = read('src/app/dashboard/ai-cover-generator.tsx');
const review = read('src/app/dashboard/draft-review.tsx');

test('generator offers both styles, checks for a saved cover, then generates', () => {
  assert.match(ui, /^"use client";?/);
  assert.match(ui, /export function AiCoverGenerator\b/);
  assert.match(ui, /<select\b/);
  assert.ok(ui.includes('AI_COVER_STYLES') && ui.includes('AI_COVER_STYLE_LABELS'));
  assert.ok(ui.includes('@/lib/ai-cover"'));
  assert.ok(ui.includes('Generate AI cover'));
  assert.ok(ui.includes('Use this image'));
  assert.ok(ui.includes('/api/cover?') && ui.includes('item=') && ui.includes('style='));
  assert.ok(ui.includes('no-store'));
  assert.match(ui, /method:\s*"POST"/);
  assert.match(ui, /item_id/);
  assert.ok(ui.includes('"bonus-generated"'));
  assert.match(ui, /\.download\(/);
  assert.match(ui, /onUse\(/);
  assert.match(ui, /if\s*\(\s*\w+\.saved\s*\)/, 'a saved result is shown without generating');
  assert.ok(ui.indexOf('/api/cover?') < ui.indexOf('method: "POST"'), 'GET before POST');
  assert.doesNotMatch(ui, /upload\(|service_role|SERVICE_ROLE/);
});

test('draft review saves the chosen cover with a fresh metadata hash', () => {
  assert.match(review, /import \{ AiCoverGenerator \} from "\.\/ai-cover-generator"/);
  assert.match(review, /editable\s*&&\s*<AiCoverGenerator\b/);
  assert.match(review, /cover_object_path:\s*\w+/);
  assert.match(review, /version:\s*2/);
  assert.ok((review.match(/metadata_sha256/g) ?? []).length >= 3);
  assert.ok((review.match(/\.eq\("status", "draft"\)/g) ?? []).length >= 2);
  assert.ok((review.match(/\.eq\("owner_id", props\.ownerId\)/g) ?? []).length >= 2);
});
