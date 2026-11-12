// Factory-owned acceptance tests for bonus-library-library-browser. The builder must make
// these pass and cannot edit them. Owner brief (Amazon-like layout, preview approved):
// summary cards, details on click, and a remembered Grid / List switch.
//   src/app/dashboard/library-browser.tsx (new): a "use client" component exported as
//     LibraryBrowser({ items }) where each item is { id, title, line, coverObjectPath,
//     details } (export type LibraryBrowserItem). It imports "./library-browser.css". It
//     renders a Grid / List toggle (buttons with aria-pressed, labelled "Grid" and "List")
//     whose choice is saved under localStorage key "bonus-library-view" inside try/catch
//     and restored after load; a list with class library-grid or library-list; one
//     <button type="button"> card per item showing a private cover thumbnail (downloaded
//     from the "bonus-generated" bucket with the browser Supabase client, or the title's
//     first letter as a placeholder), the title and the one-line summary only. Clicking a
//     card opens a native <dialog> with showModal() showing the title, a close button with
//     aria-label "Close" and the item's details. Escape (dialog close event), the close
//     button and a click on the backdrop (event.target === event.currentTarget) all close
//     it, and focus returns to the card that opened it.
//   src/app/dashboard/library-browser.css (new, plain global CSS): .dashboard-grid with one
//     column (sections stack), .library-grid as a responsive auto-fill grid, .library-list
//     with one column, and a .library-dialog::backdrop style.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const browser = read('src/app/dashboard/library-browser.tsx');
const css = read('src/app/dashboard/library-browser.css').replace(/\s+/g, '');

test('summary cards open details in an accessible dialog', () => {
  assert.match(browser, /^"use client";?/);
  assert.match(browser, /import "\.\/library-browser\.css"/);
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

test('layout styles', () => {
  assert.ok(css.includes('.dashboard-grid{grid-template-columns:1fr}'));
  assert.match(css, /\.library-grid\{[^}]*grid-template-columns:repeat\(auto-fill/);
  assert.match(css, /\.library-list\{[^}]*grid-template-columns:1fr/);
  assert.ok(css.includes('.library-dialog::backdrop{'));
});
