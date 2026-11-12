// Factory-owned acceptance tests for bonus-library-library-helpers. The builder must make
// these pass and cannot edit them. Owner-chosen features: status filter tabs, a sort menu
// and readable title suggestions. This task adds only three new pure modules with no
// imports; later tasks wire them into the dashboard.
//
//   src/lib/library-status.ts
//     export const LIBRARY_STAGES = ["uninspected", "prepared", "approved"] as const;
//     export type LibraryStage = (typeof LIBRARY_STAGES)[number];
//     export type LibraryStageFilter = LibraryStage | "all";
//     libraryItemStage(row: { status?: string | null; metadata_sha256?: string | null }):
//       "approved" when status === "approved"; otherwise "prepared" when metadata_sha256 is
//       a non-empty string; otherwise "uninspected" (the dashboard's existing rule).
//     libraryStageLabel(filter): "All" | "Uninspected" | "Prepared" | "Approved".
//     normalizeLibraryStage(raw: string | string[] | undefined): undefined, "" and "all"
//       give "all"; an exact stage name gives that stage; anything else gives null.
//     filterLibraryItemsByStage(rows, filter): new array in original order ("all" keeps all).
//     countLibraryItemsByStage(rows): { all, uninspected, prepared, approved }.
//
//   src/lib/library-sort.ts
//     export const LIBRARY_SORTS = ["newest", "oldest", "name", "size"] as const;
//     export type LibrarySort = (typeof LIBRARY_SORTS)[number];
//     export const LIBRARY_SORT_PAGE_SIZE = 10;
//     librarySortLabel(sort): "Newest" | "Oldest" | "Name" | "Size".
//     normalizeLibrarySort(raw: string | string[] | undefined): undefined and "" give
//       "newest"; an exact sort name gives it; anything else gives null.
//     sortLibraryItems(rows: { id: string; created_at: string; title?: string | null;
//       source_size_bytes?: number | null }[], sort): new array. newest = created_at
//       descending (Date.parse), oldest = ascending, size = source_size_bytes descending
//       (null as 0), name = trimmed title compared case-insensitively with localeCompare,
//       rows with an empty or missing title last. Ties break by id ascending.
//     pageLibraryItems(rows, rawPage: string | string[] | undefined): undefined is page 1;
//       otherwise a string of 1-5 digits without a leading zero. Returns { items, page,
//       pageCount } with 10 items per page and pageCount at least 1, or null for invalid
//       input or a page beyond pageCount.
//
//   src/lib/library-title.ts
//     export const LIBRARY_TITLE_MAX_LENGTH = 120;
//     suggestLibraryTitle(raw: string): trim; drop a final file extension (a dot and 1-5
//       letters/digits containing at least one letter); turn runs of "_" and "-" into
//       spaces; split lower-or-digit followed by upper ("VideoQuiz" -> "Video Quiz") and an
//       upper run before a capitalised word ("PDFGuide" -> "PDF Guide"); collapse spaces;
//       capitalise the first letter of words made only of lowercase letters and digits;
//       leave other words unchanged; cut to 120 characters and trim; "" gives
//       "Untitled bonus".
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LIBRARY_STAGES, countLibraryItemsByStage, filterLibraryItemsByStage,
  libraryItemStage, libraryStageLabel, normalizeLibraryStage,
} from '../../src/lib/library-status.ts';
import {
  LIBRARY_SORTS, LIBRARY_SORT_PAGE_SIZE, librarySortLabel, normalizeLibrarySort,
  pageLibraryItems, sortLibraryItems,
} from '../../src/lib/library-sort.ts';
import { LIBRARY_TITLE_MAX_LENGTH, suggestLibraryTitle } from '../../src/lib/library-title.ts';

const rows = [
  { id: 'a', status: 'draft', metadata_sha256: null, title: 'moviemart', created_at: '2026-09-20T10:00:00Z', source_size_bytes: 300 },
  { id: 'b', status: 'draft', metadata_sha256: 'abc', title: 'Banana', created_at: '2026-09-21T10:00:00Z', source_size_bytes: 900 },
  { id: 'c', status: 'approved', metadata_sha256: 'def', title: null, created_at: '2026-09-19T10:00:00+00:00', source_size_bytes: null },
  { id: 'd', status: 'published', metadata_sha256: '', title: 'apple', created_at: '2026-09-21T05:00:00-05:00', source_size_bytes: 900 },
  { id: 'e', status: 'rejected', metadata_sha256: 'ghi', title: '  ', created_at: '2026-09-18T10:00:00Z', source_size_bytes: 50 },
];

test('status stages, labels and strict parameter', () => {
  assert.deepEqual([...LIBRARY_STAGES], ['uninspected', 'prepared', 'approved']);
  assert.deepEqual(rows.map(libraryItemStage), ['uninspected', 'prepared', 'approved', 'uninspected', 'prepared']);
  assert.equal(libraryItemStage({}), 'uninspected');
  assert.deepEqual(['all', ...LIBRARY_STAGES].map(libraryStageLabel), ['All', 'Uninspected', 'Prepared', 'Approved']);
  for (const raw of [undefined, '', 'all']) assert.equal(normalizeLibraryStage(raw), 'all');
  for (const stage of LIBRARY_STAGES) assert.equal(normalizeLibraryStage(stage), stage);
  for (const bad of ['Approved', 'draft', ' prepared', ['approved'], 'published']) {
    assert.equal(normalizeLibraryStage(bad), null, String(bad));
  }
});

test('status filter and counts without mutation', () => {
  const snapshot = structuredClone(rows);
  const all = filterLibraryItemsByStage(rows, 'all');
  assert.notEqual(all, rows);
  assert.deepEqual(all.map((r) => r.id), ['a', 'b', 'c', 'd', 'e']);
  assert.deepEqual(filterLibraryItemsByStage(rows, 'prepared').map((r) => r.id), ['b', 'e']);
  assert.deepEqual(filterLibraryItemsByStage(rows, 'uninspected').map((r) => r.id), ['a', 'd']);
  assert.deepEqual(filterLibraryItemsByStage(rows, 'approved').map((r) => r.id), ['c']);
  assert.deepEqual(countLibraryItemsByStage(rows), { all: 5, uninspected: 2, prepared: 2, approved: 1 });
  assert.deepEqual(countLibraryItemsByStage([]), { all: 0, uninspected: 0, prepared: 0, approved: 0 });
  assert.deepEqual(rows, snapshot);
});

test('sort options and orders', () => {
  const snapshot = structuredClone(rows);
  assert.deepEqual([...LIBRARY_SORTS], ['newest', 'oldest', 'name', 'size']);
  assert.deepEqual(LIBRARY_SORTS.map(librarySortLabel), ['Newest', 'Oldest', 'Name', 'Size']);
  for (const raw of [undefined, '']) assert.equal(normalizeLibrarySort(raw), 'newest');
  for (const sort of LIBRARY_SORTS) assert.equal(normalizeLibrarySort(sort), sort);
  for (const bad of ['Name', 'title', ['size'], ' newest']) assert.equal(normalizeLibrarySort(bad), null);
  const ids = (sort) => sortLibraryItems(rows, sort).map((r) => r.id);
  // d (10:00Z) ties b (10:00Z) on time; id breaks the tie.
  assert.deepEqual(ids('newest'), ['b', 'd', 'a', 'c', 'e']);
  assert.deepEqual(ids('oldest'), ['e', 'c', 'a', 'b', 'd']);
  assert.deepEqual(ids('name'), ['d', 'b', 'a', 'c', 'e']);
  assert.deepEqual(ids('size'), ['b', 'd', 'a', 'e', 'c']);
  assert.notEqual(sortLibraryItems(rows, 'newest'), rows);
  assert.deepEqual(rows, snapshot);
});

test('page numbers for sorted views', () => {
  assert.equal(LIBRARY_SORT_PAGE_SIZE, 10);
  const many = Array.from({ length: 23 }, (_, i) => i);
  assert.deepEqual(pageLibraryItems(many, undefined), { items: many.slice(0, 10), page: 1, pageCount: 3 });
  assert.deepEqual(pageLibraryItems(many, '3'), { items: [20, 21, 22], page: 3, pageCount: 3 });
  assert.deepEqual(pageLibraryItems([], undefined), { items: [], page: 1, pageCount: 1 });
  for (const bad of ['0', '4', '01', '1.5', '-1', 'x', '123456', ['1']]) {
    assert.equal(pageLibraryItems(many, bad), null, String(bad));
  }
});

test('readable title suggestions', () => {
  const cases = {
    'chatgpt-blueprint': 'Chatgpt Blueprint',
    'SocialMediaMarketingJumpstart': 'Social Media Marketing Jumpstart',
    'Social-Media-Marketing_Guide.zip': 'Social Media Marketing Guide',
    'facebook-messenger-bot-marketing': 'Facebook Messenger Bot Marketing',
    'VideoQuizGame': 'Video Quiz Game',
    'PDFGuide v2.pdf': 'PDF Guide V2',
    'Version 1.5': 'Version 1.5',
    '  Already Good  Title ': 'Already Good Title',
    'ChatGPT___tips--and  tricks': 'Chat GPT Tips And Tricks',
    '   ': 'Untitled bonus',
    '.zip': 'Untitled bonus',
  };
  for (const [raw, expected] of Object.entries(cases)) assert.equal(suggestLibraryTitle(raw), expected, raw);
  assert.equal(LIBRARY_TITLE_MAX_LENGTH, 120);
  assert.equal(suggestLibraryTitle('word '.repeat(60)).length <= 120, true);
  assert.equal(suggestLibraryTitle('word '.repeat(60)).endsWith(' '), false);
});
