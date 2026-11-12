// Factory-owned acceptance tests for bonus-library-title-suggestion. The builder must make
// these pass and cannot edit them. Owner-chosen feature: readable title suggestions the
// owner can accept, using the merged src/lib/library-title.ts (do not change it).
//   src/app/dashboard/draft-review.tsx: import { suggestLibraryTitle } from
//     "@/lib/library-title"; compute const suggestedTitle = suggestLibraryTitle(title)
//     from the title being edited; directly after the "Reviewed title" input, while the
//     draft is editable and suggestedTitle !== title, render
//     <button className="secondary" type="button" disabled={isPending}
//       onClick={() => setTitle(suggestedTitle)}>Use suggested title: {suggestedTitle}</button>.
//     It only fills the field; the owner still saves with "Save review". Nothing else
//     changes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const review = readFileSync(new URL('../../src/app/dashboard/draft-review.tsx', import.meta.url), 'utf8').replaceAll("'", '"');

test('review offers the suggested title without saving it', () => {
  assert.match(review, /import \{ suggestLibraryTitle \} from "@\/lib\/library-title"/);
  assert.match(review, /const suggestedTitle = suggestLibraryTitle\(title\)/);
  assert.match(review, /editable && suggestedTitle !== title \?/);
  assert.match(review, /onClick=\{\(\) => setTitle\(suggestedTitle\)\}/);
  assert.match(review, /Use suggested title: \{suggestedTitle\}/);
  const input = review.indexOf('id={`title-${props.id}`}');
  const button = review.indexOf('Use suggested title');
  const description = review.indexOf('Reviewed description');
  assert.ok(input > 0 && input < button && button < description, 'button sits between the title and description');
  assert.ok(review.includes('Save review'));
  assert.ok(review.includes('Approve exact version'));
});
