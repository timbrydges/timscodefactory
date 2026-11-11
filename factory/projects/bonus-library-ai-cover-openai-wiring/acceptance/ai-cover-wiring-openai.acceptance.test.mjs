// Factory-owned acceptance tests for bonus-library-ai-cover-openai-wiring (replaces the
// Bedrock-era ai-cover-wiring acceptance tests). The builder must make these pass and
// cannot edit them. These files need real AWS, OpenAI, Supabase and Next.js, so tsc,
// eslint and the independent reviewer check behaviour; these tests pin the
// security-relevant choices in the source.
//   src/lib/ai-cover-aws.ts: imports "server-only"; exports AI_COVER_ROLE_ARN (unchanged)
//     and aiCoverBackend(upload) returning createCoverBackend(...). Throws "Not configured"
//     unless VERCEL_ENV is "production", VERCEL_GIT_COMMIT_SHA is 40 lowercase hex,
//     BONUS_AI_COVER_ROLE_ARN equals AI_COVER_ROLE_ARN and BONUS_AI_COVER_OPENAI_KEY is set.
//     DynamoDB stays in "ca-central-1" with credentials only from
//     awsCredentialsProvider({ roleArn: AI_COVER_ROLE_ARN }) and maxAttempts: 1. Bedrock is
//     no longer used. invokeModel makes exactly one fetch to AI_COVER_PROVIDER_URL (from
//     ./ai-cover) with method POST, an "Authorization: Bearer <key>" header, the given
//     body, AbortSignal.timeout(...) and no retry; a non-OK response throws a fixed error
//     that never includes the response text; it returns the response bytes.
//   src/lib/ai-cover.ts: buildCoverRequest uses exactly the owner-approved prompts from the
//     owner's gpt-image-2 test (with T the trimmed title, double quotes replaced by single):
//     ebook: Professional 3D product mockup photo of a hardcover book standing upright at a
//       slight angle on a clean light surface, soft studio lighting, realistic shadow. The
//       front cover shows the title "T" in large bold modern typography, spelled exactly,
//       with an elegant abstract design. No people, no other words.
//     software_box: Professional 3D product mockup photo of a retail software box at a
//       three-quarter angle on a clean light background, soft studio lighting, realistic
//       shadow. The front and spine show the product name "T" in bold modern typography,
//       spelled exactly, with a sleek abstract tech design. No people, no other words.
//     (single spaces between sentences; nothing else in ai-cover.ts changes).
//   src/app/api/cover/route.ts: unchanged authorization and upload rules (owner, draft,
//     bonus-generated, upsert: false, the user's own Supabase session) and
//     maxDuration = 300 so an image can finish.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { buildCoverRequest } from '../../src/lib/ai-cover.ts';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const aws = read('src/lib/ai-cover-aws.ts');
const route = read('src/app/api/cover/route.ts').replaceAll("'", '"');

test('backend keeps the AWS budget role and calls OpenAI once with the website key', () => {
  assert.match(aws, /^import ["']server-only["'];?/m);
  assert.ok(aws.includes('arn:aws:iam::666730517561:role/tims-software-factory-bonus-ai-cover-web'));
  assert.match(aws, /export function aiCoverBackend\b/);
  assert.match(aws, /awsCredentialsProvider\(\s*\{\s*roleArn:\s*AI_COVER_ROLE_ARN\s*\}\s*\)/);
  assert.match(aws, /BONUS_AI_COVER_ROLE_ARN\s*!==\s*AI_COVER_ROLE_ARN/);
  assert.ok(aws.includes('BONUS_AI_COVER_OPENAI_KEY'));
  // The configuration check that throws "Not configured" must test the website key.
  const named = aws.match(/const (\w+)\s*=\s*process\.env\.BONUS_AI_COVER_OPENAI_KEY/);
  const key = named ? named[1] : 'process.env.BONUS_AI_COVER_OPENAI_KEY';
  const end = aws.indexOf('Not configured');
  const guard = aws.slice(aws.lastIndexOf('if (', end), end);
  assert.ok(guard.includes(key), 'the Not configured guard checks the OpenAI key');
  assert.match(aws, /VERCEL_ENV\s*!==\s*["']production["']/);
  assert.ok(aws.includes('Not configured'));
  assert.ok(aws.includes('"ca-central-1"') || aws.includes("'ca-central-1'"));
  assert.match(aws, /maxAttempts:\s*1\b/);
  assert.doesNotMatch(aws, /maxAttempts:\s*[2-9]/);
  assert.doesNotMatch(aws, /BedrockRuntimeClient|InvokeModelCommand|client-bedrock/);
  assert.equal((aws.match(/\bfetch\(/g) ?? []).length, 1);
  assert.match(aws, /fetch\(\s*AI_COVER_PROVIDER_URL/);
  assert.match(aws, /method:\s*["']POST["']/);
  assert.match(aws, /Authorization:\s*`Bearer \$\{/);
  assert.match(aws, /AbortSignal\.timeout\(/);
  assert.match(aws, /response\.ok/);
  assert.doesNotMatch(aws, /response\.text\(\)|await response\.json\(\)|accessKeyId|secretAccessKey|SERVICE_ROLE/i);
  assert.match(aws, /createCoverBackend\(/);
});

test('route keeps owner, draft and private-upload rules and allows five minutes', () => {
  assert.match(route, /export const runtime\s*=\s*"nodejs"/);
  assert.match(route, /export const maxDuration\s*=\s*300\b/);
  assert.match(route, /export async function GET\b/);
  assert.match(route, /export async function POST\b/);
  assert.match(route, /\.eq\(\s*"status"\s*,\s*"draft"\s*\)/);
  assert.match(route, /\.eq\(\s*"owner_id"\s*,/);
  for (const term of ['bonus_library_owners', 'library_items', 'auth.getUser()', '"bonus-generated"',
    'upsert: false', '@/lib/supabase/server', 'BONUS_AI_COVER_ACTIVATION_SHA']) {
    assert.ok(route.includes(term), term);
  }
  assert.doesNotMatch(route, /SERVICE_ROLE|service_role|OPENAI/i);
});

test('prompts are exactly the owner-approved wording', () => {
  assert.equal(buildCoverRequest('  Streaming "Profits" Authority ', 'ebook').prompt,
    'Professional 3D product mockup photo of a hardcover book standing upright at a slight angle on a clean light surface, ' +
    "soft studio lighting, realistic shadow. The front cover shows the title \"Streaming 'Profits' Authority\" in large bold " +
    'modern typography, spelled exactly, with an elegant abstract design. No people, no other words.');
  assert.equal(buildCoverRequest('Pixel Studio Pro', 'software_box').prompt,
    'Professional 3D product mockup photo of a retail software box at a three-quarter angle on a clean light background, ' +
    'soft studio lighting, realistic shadow. The front and spine show the product name "Pixel Studio Pro" in bold modern ' +
    'typography, spelled exactly, with a sleek abstract tech design. No people, no other words.');
});
