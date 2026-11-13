// Factory-owned acceptance tests for bonus-library-library-archive. The builder must make
// these pass and cannot edit them. Owner-chosen feature: archive test or unwanted draft
// items so they are hidden from the dashboard, restorable and never deleted.
//   supabase/migrations/20261113000000_owner_archive.sql (new; the owner applies it in
//     Supabase before deploying): exactly
//       alter table public.library_items add column if not exists archived_at timestamptz;
//       grant update (archived_at) on public.library_items to authenticated;
//     plus comments. No other statement (the existing RLS policy and lifecycle trigger
//     already limit updates to the owner's draft items; approved items stay immutable).
//   src/app/dashboard/archive-control.tsx (new, "use client"): export function
//     ArchiveControl({ id, ownerId, archived }) with one <button type="button"> labelled
//     "Archive item" or "Restore item" that updates library_items.archived_at (an ISO
//     timestamp, or null to restore) with .eq("id", id).eq("owner_id", ownerId)
//     .eq("status", "draft") through the browser Supabase client, shows the result in an
//     aria-live message and refreshes the page (router.refresh in a transition).
//   src/lib/library-search.ts: libraryPageHref also accepts archived (default false) and
//     adds archived=1 after page when true.
//   src/app/dashboard/page.tsx: selects archived_at; params.archived === "1" shows only
//     archived rows, otherwise only active rows (before search, stage and sort); a link
//     "Show archived items (<count>)" when any exist, or "Back to active items" while
//     viewing them; every view link and both GET forms keep archived; each draft's
//     details end with <ArchiveControl id ownerId archived />.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { libraryPageHref } from '../../src/lib/library-search.ts';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const migration = read('supabase/migrations/20261113000000_owner_archive.sql');
const control = read('src/app/dashboard/archive-control.tsx');
const page = read('src/app/dashboard/page.tsx');

test('migration only adds the column and its update grant', () => {
  const statements = migration.replace(/--[^\n]*/g, '').split(';').map((s) => s.replace(/\s+/g, ' ').trim()).filter(Boolean);
  assert.deepEqual(statements, [
    'alter table public.library_items add column if not exists archived_at timestamptz',
    'grant update (archived_at) on public.library_items to authenticated',
  ]);
});

test('archive control updates only the owner draft and refreshes', () => {
  assert.match(control, /^"use client";?/);
  assert.match(control, /export function ArchiveControl\b/);
  assert.match(control, /\.from\("library_items"\)/);
  assert.match(control, /archived_at:/);
  assert.match(control, /\.eq\("id", id\)/);
  assert.match(control, /\.eq\("owner_id", ownerId\)/);
  assert.match(control, /\.eq\("status", "draft"\)/);
  assert.ok(control.includes('Archive item') && control.includes('Restore item'));
  assert.match(control, /type="button"/);
  assert.match(control, /aria-live="polite"/);
  assert.match(control, /router\.refresh\(\)/);
  assert.doesNotMatch(control, /\.delete\(/);
});

test('links keep the archived view', () => {
  assert.equal(libraryPageHref({ q: '', cursor: null, direction: null, archived: false }), '/dashboard');
  assert.equal(libraryPageHref({ q: 'x', cursor: null, direction: null, sort: 'size', page: 2, archived: true }),
    '/dashboard?q=x&sort=size&page=2&archived=1');
});

test('dashboard hides archived items by default and offers the control', () => {
  assert.match(page, /archived_at"\)/);
  assert.match(page, /params\.archived === "1"/);
  assert.ok(page.includes('Show archived items ('));
  assert.ok(page.includes('Back to active items'));
  assert.match(page, /name="archived" value="1"/);
  assert.match(page, /<ArchiveControl\b[^>]*archived=\{draft\.archived_at !== null\}/s);
  assert.match(page, /import \{ ArchiveControl \} from "@\/app\/dashboard\/archive-control"/);
  assert.ok(page.includes('aria-label="Status filter"'));
  assert.ok(page.includes('aria-label="Library pages"'));
});
