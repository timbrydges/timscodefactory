// Factory-owned acceptance tests for bonus-library-pagination. The builder must
// make these pass and cannot edit them. Contract: src/lib/library-pagination.ts
// exports LIBRARY_PAGE_SIZE (10) and
//   paginateLibraryItems(rows, ownerId, { cursor, direction })
// rows: { id, created_at, owner_id }[] in any order. Items are newest first
// (created_at desc, then id desc). Returns { items, olderCursor, newerCursor },
// where a cursor is an opaque string or null and is non-null exactly when more
// rows exist in that direction. Returns null for malformed input.
import test from 'node:test';
import assert from 'node:assert/strict';
import { LIBRARY_PAGE_SIZE, paginateLibraryItems } from '../../src/lib/library-pagination.ts';

const OWNER = 'owner-a';
const OTHER = 'owner-b';

function uuid(n) {
  return `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
}

function rows(count, { owner = OWNER, sameTime = false, offset = 0 } = {}) {
  return Array.from({ length: count }, (_, i) => ({
    id: uuid(offset + i + 1),
    created_at: new Date(Date.UTC(2026, 0, 1, 0, 0, sameTime ? 0 : offset + i)).toISOString(),
    owner_id: owner,
  }));
}

function expectedOrder(all, owner = OWNER) {
  return all.filter((row) => row.owner_id === owner).sort((a, b) =>
    a.created_at === b.created_at ? (a.id < b.id ? 1 : -1) : (a.created_at < b.created_at ? 1 : -1));
}

const ids = (page) => page.items.map((row) => row.id);

function walk(all, owner = OWNER) {
  const pages = [paginateLibraryItems(all, owner, { cursor: null, direction: null })];
  while (pages.at(-1).olderCursor && pages.length < 20) {
    pages.push(paginateLibraryItems(all, owner, { cursor: pages.at(-1).olderCursor, direction: 'older' }));
  }
  return pages;
}

test('page size is ten', () => {
  assert.equal(LIBRARY_PAGE_SIZE, 10);
});

test('more than ten items are reachable older then newer with correct links on every page', () => {
  const all = rows(25);
  const order = expectedOrder(all).map((row) => row.id);
  const pages = walk(all);
  assert.deepEqual(pages.map((page) => page.items.length), [10, 10, 5]);
  assert.deepEqual(pages.flatMap(ids), order);
  assert.equal(pages[0].newerCursor, null);
  assert.notEqual(pages[0].olderCursor, null);
  assert.notEqual(pages[1].newerCursor, null);
  assert.notEqual(pages[1].olderCursor, null);
  assert.notEqual(pages[2].newerCursor, null);
  assert.equal(pages[2].olderCursor, null);

  const back2 = paginateLibraryItems(all, OWNER, { cursor: pages[2].newerCursor, direction: 'newer' });
  assert.deepEqual(ids(back2), ids(pages[1]));
  assert.notEqual(back2.olderCursor, null, 'Older link must remain after navigating newer');
  assert.notEqual(back2.newerCursor, null);
  const back1 = paginateLibraryItems(all, OWNER, { cursor: back2.newerCursor, direction: 'newer' });
  assert.deepEqual(ids(back1), ids(pages[0]));
  assert.equal(back1.newerCursor, null, 'first page has no Newer link');
  assert.notEqual(back1.olderCursor, null, 'first page keeps its Older link');
});

test('exactly ten items fit on one page with no links', () => {
  const page = paginateLibraryItems(rows(10), OWNER, { cursor: null, direction: null });
  assert.equal(page.items.length, 10);
  assert.equal(page.olderCursor, null);
  assert.equal(page.newerCursor, null);
});

test('equal timestamps are ordered by id without duplicates or omissions in both directions', () => {
  const all = rows(23, { sameTime: true });
  const order = expectedOrder(all).map((row) => row.id);
  const pages = walk(all);
  assert.deepEqual(pages.flatMap(ids), order);
  let page = pages.at(-1);
  const backwards = [ids(page)];
  while (page.newerCursor) {
    page = paginateLibraryItems(all, OWNER, { cursor: page.newerCursor, direction: 'newer' });
    backwards.unshift(ids(page));
    assert.ok(backwards.length < 20);
  }
  assert.deepEqual(backwards.flat(), order);
});

test('other owners never appear and a cursor cannot change owner scope', () => {
  const all = [...rows(15), ...rows(15, { owner: OTHER, offset: 100 })];
  const pages = walk(all);
  assert.deepEqual(pages.flatMap(ids), expectedOrder(all).map((row) => row.id));
  const otherPage = paginateLibraryItems(all, OTHER, { cursor: null, direction: null });
  const crossed = paginateLibraryItems(all, OWNER, { cursor: otherPage.olderCursor, direction: 'older' });
  if (crossed !== null) {
    assert.ok(crossed.items.every((row) => row.owner_id === OWNER));
  }
});

test('empty libraries have no items and no links', () => {
  const page = paginateLibraryItems([], OWNER, { cursor: null, direction: null });
  assert.deepEqual(page.items, []);
  assert.equal(page.olderCursor, null);
  assert.equal(page.newerCursor, null);
});

test('malformed cursors and directions are rejected', () => {
  const all = rows(25);
  const valid = paginateLibraryItems(all, OWNER, { cursor: null, direction: null }).olderCursor;
  for (const request of [
    { cursor: 'not-a-cursor', direction: 'older' },
    { cursor: `${valid}!`, direction: 'older' },
    { cursor: valid, direction: 'sideways' },
    { cursor: valid, direction: null },
    { cursor: null, direction: 'older' },
  ]) {
    assert.equal(paginateLibraryItems(all, OWNER, request), null, JSON.stringify(request));
  }
});
