// Factory-owned acceptance tests for bonus-library-library-toolbar. The builder must make
// these pass and cannot edit them. Owner-chosen features: status filter tabs with counts
// and a sort menu, using the merged helpers in src/lib/library-status.ts and
// src/lib/library-sort.ts (do not change them).
//   src/lib/library-search.ts: libraryPageHref also accepts optional status (default
//     "all"), sort (default "newest") and page (default 1) and adds each only when it
//     differs from its default, in the order q, status, sort, page, cursor, direction.
//   src/app/dashboard/page.tsx: reads status and sort with normalizeLibraryStage and
//     normalizeLibrarySort (invalid values show the existing load-failure alert); counts
//     the search results per stage, filters them by stage, then for "newest" keeps the
//     existing cursor pagination (Newer / Older) and for other sorts uses
//     pageLibraryItems(sortLibraryItems(rows, sort), params.page) with Previous / Next
//     links. Renders <nav className="status-tabs" aria-label="Status filter"> with one
//     Link per tab (All, Uninspected, Prepared, Approved) labelled "<Label> (<count>)" and
//     aria-current="page" on the active tab, and a GET form with a <select name="sort">
//     of the four sort labels. The search form and both new controls keep the other view
//     settings (hidden inputs / libraryPageHref).
//   src/app/dashboard/library-browser.css: .status-tabs (wrapping row of pill links, the
//     aria-current="page" tab in var(--accent) with white text) and .sort-form styles, and
//     fix the unselected Grid / List button, which inherits the global white button text:
//     .view-toggle button[aria-pressed="false"] { color: var(--ink); }
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { libraryPageHref } from '../../src/lib/library-search.ts';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const page = read('src/app/dashboard/page.tsx');
const css = read('src/app/dashboard/library-browser.css').replace(/\s+/g, '');

test('links carry only non-default view settings', () => {
  assert.equal(libraryPageHref({ q: '', cursor: null, direction: null }), '/dashboard');
  assert.equal(libraryPageHref({ q: '', cursor: null, direction: null, status: 'all', sort: 'newest', page: 1 }), '/dashboard');
  assert.equal(libraryPageHref({ q: 'atlas', cursor: null, direction: null, status: 'approved', sort: 'name', page: 2 }),
    '/dashboard?q=atlas&status=approved&sort=name&page=2');
  assert.equal(libraryPageHref({ q: '', cursor: 'abc', direction: 'older', status: 'prepared' }),
    '/dashboard?status=prepared&cursor=abc&direction=older');
});

test('dashboard renders status tabs and a sort menu', () => {
  assert.match(page, /from "@\/lib\/library-status"/);
  assert.match(page, /from "@\/lib\/library-sort"/);
  for (const name of ['normalizeLibraryStage', 'filterLibraryItemsByStage', 'countLibraryItemsByStage',
    'libraryStageLabel', 'normalizeLibrarySort', 'sortLibraryItems', 'pageLibraryItems', 'librarySortLabel']) {
    assert.match(page, new RegExp(`\\b${name}\\(`), name);
  }
  assert.match(page, /params\.status/);
  assert.match(page, /params\.sort/);
  assert.match(page, /params\.page/);
  assert.ok(page.includes('aria-label="Status filter"'));
  assert.ok(page.includes('className="status-tabs"'));
  assert.match(page, /aria-current=\{[^}]*"page"/);
  assert.match(page, /<select[^>]*name="sort"/s);
  assert.ok(page.includes('>Previous<') || /\n\s*Previous\n/.test(page));
  assert.ok(page.includes('>Next<') || /\n\s*Next\n/.test(page));
  assert.ok(page.includes('aria-label="Library pages"'));
  assert.ok(page.includes('role="search"'));
  assert.ok(page.includes('.from("library_items")'));
  assert.match(page, /name="status"/);
});

test('toolbar styles', () => {
  assert.match(css, /\.status-tabs\{[^}]*display:flex/);
  assert.match(css, /\.status-tabsa\[aria-current="page"\]\{[^}]*background:var\(--accent\)/);
  assert.ok(css.includes('.sort-form{'));
  assert.ok(css.includes('.view-toggle button[aria-pressed="false"]{color:var(--ink)'.replace(/\s+/g, '')));
});
