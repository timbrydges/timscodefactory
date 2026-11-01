// Factory-owned acceptance tests for bonus-library-search. The builder must make
// these pass and cannot edit them. Contract: src/lib/library-search.ts exports
//   LIBRARY_SEARCH_MAX_LENGTH (100)
//   normalizeLibrarySearch(raw: string | string[] | undefined): string | null
//     undefined -> ""; trims and collapses runs of spaces; null for arrays, other
//     control characters (including tabs and newlines) or more than 100 characters.
//   filterLibraryItemsByTitle(rows, query): rows whose string title contains the
//     query case-insensitively, in input order, without mutating rows; "" keeps all.
//   libraryPageHref({ q, cursor, direction }): "/dashboard" plus only the non-empty
//     parameters, so paging links keep the active search.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LIBRARY_SEARCH_MAX_LENGTH,
  filterLibraryItemsByTitle,
  libraryPageHref,
  normalizeLibrarySearch,
} from '../../src/lib/library-search.ts';
import { paginateLibraryItems } from '../../src/lib/library-pagination.ts';

const OWNER = 'owner-a';

function uuid(n) {
  return `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
}

function item(n, title) {
  return { id: uuid(n), created_at: new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString(), owner_id: OWNER, title };
}

test('search length limit is 100 characters', () => {
  assert.equal(LIBRARY_SEARCH_MAX_LENGTH, 100);
  assert.equal(normalizeLibrarySearch('x'.repeat(100)), 'x'.repeat(100));
  assert.equal(normalizeLibrarySearch('x'.repeat(101)), null);
});

test('search input is normalized or rejected', () => {
  assert.equal(normalizeLibrarySearch(undefined), '');
  assert.equal(normalizeLibrarySearch(''), '');
  assert.equal(normalizeLibrarySearch('   '), '');
  assert.equal(normalizeLibrarySearch('  Space   Odyssey '), 'Space Odyssey');
  for (const bad of [['a', 'b'], 'a\tb', 'a\nb', 'a\u0000b', 'a\u007fb']) {
    assert.equal(normalizeLibrarySearch(bad), null, JSON.stringify(bad));
  }
});

test('titles match case-insensitively and literally, in input order', () => {
  const rows = [item(1, 'Dragon Tales'), item(2, 'Sea Stories'), item(3, 'DRAGONS of Ice'),
    item(4, null), item(5, 'C++ (2nd) Guide'), item(6, 'the dragon')];
  const snapshot = JSON.stringify(rows);
  assert.deepEqual(filterLibraryItemsByTitle(rows, 'dragon').map((row) => row.id),
    [uuid(1), uuid(3), uuid(6)]);
  assert.deepEqual(filterLibraryItemsByTitle(rows, 'c++ (2nd)').map((row) => row.id), [uuid(5)]);
  assert.deepEqual(filterLibraryItemsByTitle(rows, 'missing'), []);
  assert.deepEqual(filterLibraryItemsByTitle(rows, '').map((row) => row.id), rows.map((row) => row.id));
  assert.equal(JSON.stringify(rows), snapshot, 'input rows are not mutated');
});

test('search results page with Older and Newer navigation', () => {
  const rows = [];
  for (let n = 1; n <= 40; n += 1) rows.push(item(n, n % 4 === 0 ? `Atlas ${n}` : `Dragon ${n}`));
  const matches = filterLibraryItemsByTitle(rows, 'dragon');
  assert.equal(matches.length, 30);
  const first = paginateLibraryItems(matches, OWNER, { cursor: null, direction: null });
  const second = paginateLibraryItems(matches, OWNER, { cursor: first.olderCursor, direction: 'older' });
  const third = paginateLibraryItems(matches, OWNER, { cursor: second.olderCursor, direction: 'older' });
  const all = [...first.items, ...second.items, ...third.items];
  assert.equal(all.length, 30);
  assert.ok(all.every((row) => row.title.startsWith('Dragon')));
  assert.equal(third.olderCursor, null);
  const back = paginateLibraryItems(matches, OWNER, { cursor: third.newerCursor, direction: 'newer' });
  assert.deepEqual(back.items.map((row) => row.id), second.items.map((row) => row.id));
});

test('page links keep the search and omit empty parameters', () => {
  assert.equal(libraryPageHref({ q: '', cursor: null, direction: null }), '/dashboard');
  const href = new URL(libraryPageHref({ q: 'dragon & sea', cursor: 'abc_-1', direction: 'older' }), 'http://local');
  assert.equal(href.pathname, '/dashboard');
  assert.equal(href.searchParams.get('q'), 'dragon & sea');
  assert.equal(href.searchParams.get('cursor'), 'abc_-1');
  assert.equal(href.searchParams.get('direction'), 'older');
  const plain = new URL(libraryPageHref({ q: '', cursor: 'abc', direction: 'newer' }), 'http://local');
  assert.equal(plain.searchParams.has('q'), false);
  const searchOnly = new URL(libraryPageHref({ q: 'atlas', cursor: null, direction: null }), 'http://local');
  assert.deepEqual([...searchOnly.searchParams.keys()], ['q']);
});
