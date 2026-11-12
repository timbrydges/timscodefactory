// Factory-owned acceptance tests for bonus-library-library-page. The builder must make
// these pass and cannot edit them.
//   src/app/dashboard/page.tsx renders LibraryBrowser (from
//     "@/app/dashboard/library-browser") instead of the always-expanded draft list; each
//     item is { id, title, line: "<size MB> · <date en-CA> · <Approved|Prepared|Uninspected>",
//     coverObjectPath, details } and details are the existing DraftInspector and DraftReview
//     elements with the same props and conditions. The data query, search form and
//     Newer / Older navigation remain unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const page = read('src/app/dashboard/page.tsx');

test('page keeps its data, search and paging but hides details until clicked', () => {
  assert.match(page, /import \{ LibraryBrowser \} from "@\/app\/dashboard\/library-browser"/);
  assert.match(page, /<LibraryBrowser\b/);
  assert.doesNotMatch(page, /className="draft-list"/);
  assert.match(page, /draft\.status === "draft" \? \(\s*<DraftInspector\b/);
  assert.match(page, /draft\.cover_object_path && draft\.metadata_sha256 \? \(\s*<DraftReview\b/);
  assert.match(page, /<DraftReview\b/);
  assert.ok(page.includes('role="search"'));
  assert.ok(page.includes('aria-label="Library pages"'));
  assert.ok(page.includes('.from("library_items")'));
});

