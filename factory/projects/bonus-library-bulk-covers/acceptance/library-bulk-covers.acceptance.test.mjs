// Factory-owned acceptance tests for bonus-library-bulk-covers. The builder must make these
// pass and cannot edit them. Owner-chosen feature: generate AI covers for several prepared
// drafts in one run, within the existing AI cover budget; the owner still chooses
// "Use this image" on each item.
//   src/app/dashboard/bulk-cover-generator.tsx (new, "use client"): exports
//     BULK_COVER_LIMIT = 10, BULK_COVER_RESERVE_USD = 0.1 and
//     BulkCoverGenerator({ items }: { items: { id: string; title: string }[] }). Renders
//     nothing for no items; otherwise a <section aria-label="Bulk AI covers"> with a style
//     <select> of AI_COVER_STYLES / AI_COVER_STYLE_LABELS, a "Generate N covers" button that
//     first asks for confirmation showing the maximum spend (batch size x US$0.10) with
//     "Confirm and generate" and "Cancel", and an aria-live log. On confirmation it handles
//     at most the first 10 items one at a time: GET /api/cover?item=&style= (cache
//     "no-store"); skip an item with a saved cover; stop when generation is not enabled;
//     otherwise POST /api/cover { item_id, style } and stop at the first failure (never
//     retried automatically). It never calls "Use this image" or changes library_items.
//   src/app/dashboard/page.tsx: passes the active draft rows with status "draft", a
//     metadata_sha256, a non-empty title and a cover_object_path that does not contain
//     "-ai-cover-" to <BulkCoverGenerator items=... /> in the "New draft" section.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const bulk = read('src/app/dashboard/bulk-cover-generator.tsx');
const page = read('src/app/dashboard/page.tsx');

test('bulk generator is bounded, confirmed and sequential', () => {
  assert.match(bulk, /^"use client";?/);
  assert.match(bulk, /export const BULK_COVER_LIMIT = 10\b/);
  assert.match(bulk, /export const BULK_COVER_RESERVE_USD = 0\.1\b/);
  assert.match(bulk, /export function BulkCoverGenerator\b/);
  assert.match(bulk, /\.slice\(0, BULK_COVER_LIMIT\)/);
  assert.match(bulk, /aria-label="Bulk AI covers"/);
  assert.ok(bulk.includes('Confirm and generate') && bulk.includes('Cancel'));
  assert.match(bulk, /for \(const item of /);
  assert.match(bulk, /await fetch\(`\/api\/cover\?/);
  assert.match(bulk, /cache: "no-store"/);
  assert.match(bulk, /method: "POST"/);
  assert.match(bulk, /item_id: item\.id/);
  assert.match(bulk, /AI_COVER_STYLES/);
  assert.match(bulk, /aria-live="polite"/);
  assert.doesNotMatch(bulk, /library_items|\.update\(|createClient/);
  assert.ok(bulk.indexOf('status.saved') < bulk.indexOf('method: "POST"'), 'checks for a saved cover first');
  assert.ok(bulk.indexOf('!status.enabled') < bulk.indexOf('method: "POST"'), 'stops when not enabled');
});

test('dashboard offers only eligible prepared drafts', () => {
  assert.match(page, /import \{ BulkCoverGenerator \} from "@\/app\/dashboard\/bulk-cover-generator"/);
  assert.match(page, /<BulkCoverGenerator items=\{/);
  assert.ok(page.includes('"-ai-cover-"'));
  assert.match(page, /status === "draft"/);
  assert.match(page, /metadata_sha256/);
});
