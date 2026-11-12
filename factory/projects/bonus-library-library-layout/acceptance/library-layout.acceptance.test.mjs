// Factory-owned acceptance tests for bonus-library-library-layout. The builder must make
// these pass and cannot edit them. Owner brief: summary cards, details on click, and a
// remembered Grid / List switch; presentation only (no data, API or routing changes).
//   src/app/dashboard/library-browser.tsx: a "use client" component exported as
//     LibraryBrowser({ items }) where each item is { id, title, line, coverObjectPath,
//     details }. It renders a Grid / List toggle (buttons with aria-pressed, labelled
//     "Grid" and "List") whose choice is saved under localStorage key "bonus-library-view"
//     inside try/catch and restored after load; a list with class library-grid or
//     library-list; one <button type="button"> card per item showing a private cover
//     thumbnail (downloaded from the "bonus-generated" bucket, or a placeholder), the
//     title and the one-line summary only. Clicking a card opens a native <dialog> with
//     showModal() showing the title, a close button with aria-label "Close" and the
//     item's details. Escape (dialog close event), the close button and a click on the
//     backdrop (event.target === event.currentTarget) all close it, and focus returns to
//     the card that opened it.
//   src/app/dashboard/page.tsx renders LibraryBrowser instead of the always-expanded
//     draft list; each item's details are the existing DraftInspector and DraftReview
//     (same props and conditions). The search form and Newer / Older navigation remain.
//   src/app/globals.css: the dashboard sections stack (.dashboard-grid with one column),
//     .library-grid is a responsive auto-fill grid, .library-list is one column, and the
//     dialog has a ::backdrop style.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const browser = read('src/app/dashboard/library-browser.tsx');
const page = read('src/app/dashboard/page.tsx');
const css = read('src/app/globals.css').replace(/\s+/g, '');

test('summary cards open details in an accessible dialog', () => {
  assert.match(browser, /^"use client";?/);
  assert.match(browser, /export function LibraryBrowser\b/);
  for (const field of ['title', 'line', 'coverObjectPath', 'details']) assert.ok(browser.includes(field), field);
  assert.match(browser, /<button[^>]*type="button"/s);
  assert.ok(browser.includes('"bonus-generated"'));
  assert.match(browser, /<dialog\b/);
  assert.match(browser, /\.showModal\(\)/);
  assert.match(browser, /aria-label="Close"/);
  assert.match(browser, /event\.target\s*===\s*event\.currentTarget/);
  assert.match(browser, /onClose=|addEventListener\(\s*"close"/);
  assert.match(browser, /\.focus\(\)/);
});

test('grid and list switch is remembered on this device', () => {
  assert.ok(browser.includes('"bonus-library-view"'));
  assert.match(browser, /localStorage\.setItem/);
  assert.match(browser, /localStorage\.getItem/);
  assert.match(browser, /try\s*\{[\s\S]*localStorage/);
  assert.match(browser, /aria-pressed=/);
  assert.ok(browser.includes('>Grid<') && browser.includes('>List<'));
  assert.ok(browser.includes('library-grid') || browser.includes('library-${'));
});

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

test('layout styles', () => {
  assert.ok(css.includes('.dashboard-grid{grid-template-columns:1fr}'));
  assert.match(css, /\.library-grid\{[^}]*grid-template-columns:repeat\(auto-fill/);
  assert.match(css, /\.library-list\{[^}]*grid-template-columns:1fr/);
  assert.ok(css.includes('.library-dialog::backdrop{'));
});
