// Factory-owned acceptance tests for bonus-library-ai-cover-preview. The builder must make
// these pass and cannot edit them. The owner saw the first live gpt-image-2 cover squashed
// into a 1200x630 box and generated from a file-name title.
//   src/app/dashboard/ai-cover-generator.tsx: Props gain title: string; before generating,
//     the component shows "Uses the saved title:" followed by the trimmed title (or
//     "(no title)") and says to edit and save the title first if needed. The preview
//     image keeps the real shape: width 1024 and height 1536 for ebook or 1024 for
//     software_box (never 1200 by 630).
//   src/app/dashboard/draft-review.tsx passes title={savedTitle} to AiCoverGenerator.
//   src/app/globals.css: .cover-frame no longer forces a 1200/630 box (aspect-ratio: auto)
//     and its image uses height: auto with object-fit: contain; .ai-cover-preview img uses
//     height: auto, max-width: 100% and object-fit: contain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll("'", '"');
const ui = read('src/app/dashboard/ai-cover-generator.tsx');
const review = read('src/app/dashboard/draft-review.tsx');
const css = read('src/app/globals.css').replace(/\s+/g, '');

test('generator shows the title it will use and keeps the image shape', () => {
  assert.match(ui, /title:\s*string/);
  assert.ok(ui.includes('Uses the saved title:'));
  assert.ok(ui.includes('(no title)'));
  assert.match(ui, /title\.trim\(\)/);
  assert.match(ui, /1536/);
  assert.match(ui, /width=\{1024\}|width:\s*1024/);
  assert.doesNotMatch(ui, /width=\{1200\}|height=\{630\}/);
  assert.match(review, /<AiCoverGenerator[^>]*title=\{savedTitle\}/s);
});

test('cover frame and preview never stretch the image', () => {
  const rule = (selector) => {
    const all = [...css.matchAll(new RegExp(selector.replace(/[.*]/g, '\\$&') + '\\{([^}]*)\\}', 'g'))];
    return all.map((m) => m[1]).join(';');
  };
  assert.match(rule('.cover-frame'), /aspect-ratio:auto/);
  assert.match(rule('.cover-frameimg'), /height:auto/);
  assert.match(rule('.cover-frameimg'), /object-fit:contain/);
  const preview = rule('.ai-cover-previewimg');
  for (const part of ['height:auto', 'max-width:100%', 'object-fit:contain']) assert.ok(preview.includes(part), part);
});
