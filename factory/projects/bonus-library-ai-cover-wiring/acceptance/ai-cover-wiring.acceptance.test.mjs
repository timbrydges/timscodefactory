// Factory-owned acceptance tests for bonus-library-ai-cover-wiring. The builder must
// make these pass and cannot edit them. These files need real AWS, Supabase and Next.js,
// so tsc, eslint and the independent reviewer check behaviour; these tests pin the
// security-relevant choices in the source.
//   src/lib/ai-cover-aws.ts: imports "server-only"; exports AI_COVER_ROLE_ARN
//     ("arn:aws:iam::666730517561:role/tims-software-factory-bonus-ai-cover-web") and
//     aiCoverBackend(upload) returning createCoverBackend(...) from ./ai-cover-backend.
//     Throws "Not configured" unless VERCEL_ENV is "production", VERCEL_GIT_COMMIT_SHA is
//     40 lowercase hex and BONUS_AI_COVER_ROLE_ARN equals AI_COVER_ROLE_ARN. Credentials
//     come only from awsCredentialsProvider({ roleArn: AI_COVER_ROLE_ARN })
//     (@vercel/oidc-aws-credentials-provider). DynamoDB uses region "ca-central-1",
//     Bedrock uses AI_COVER_REGION; both clients use maxAttempts: 1.
//   src/app/api/cover/route.ts: runtime "nodejs"; GET and POST both call coverRequest.
//     authorize requires a signed-in user listed in bonus_library_owners and a
//     library_items row with that id, owner_id = the user and status "draft" with a
//     non-empty title. Uploads go to the "bonus-generated" bucket with upsert: false
//     using the signed-in user's server Supabase client (no service-role key).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const aws = read('src/lib/ai-cover-aws.ts');
const route = read('src/app/api/cover/route.ts');

test('AWS backend is server-only, pinned to one role and never retries', () => {
  assert.match(aws, /^import ["']server-only["'];?/m);
  assert.ok(aws.includes('arn:aws:iam::666730517561:role/tims-software-factory-bonus-ai-cover-web'));
  assert.match(aws, /export const AI_COVER_ROLE_ARN\b/);
  assert.match(aws, /export function aiCoverBackend\b/);
  assert.match(aws, /awsCredentialsProvider\(\s*\{\s*roleArn:\s*AI_COVER_ROLE_ARN\s*\}\s*\)/);
  assert.match(aws, /BONUS_AI_COVER_ROLE_ARN\s*!==\s*AI_COVER_ROLE_ARN|AI_COVER_ROLE_ARN\s*!==\s*process\.env\.BONUS_AI_COVER_ROLE_ARN/);
  assert.match(aws, /VERCEL_ENV\s*!==\s*["']production["']/);
  assert.ok(aws.includes('Not configured'));
  assert.ok(aws.includes('"ca-central-1"') || aws.includes("'ca-central-1'"));
  assert.match(aws, /region:\s*AI_COVER_REGION/);
  assert.equal((aws.match(/maxAttempts:\s*1\b/g) ?? []).length >= 1, true);
  assert.doesNotMatch(aws, /maxAttempts:\s*[2-9]/);
  assert.match(aws, /createCoverBackend\(/);
  assert.doesNotMatch(aws, /accessKeyId|secretAccessKey|SERVICE_ROLE/i);
});

test('route authorizes the owner and draft item and uploads with the user session', () => {
  assert.match(route, /export const runtime\s*=\s*["']nodejs["']/);
  assert.match(route, /export async function GET\b/);
  assert.match(route, /export async function POST\b/);
  assert.equal((route.match(/coverRequest\(/g) ?? []).length >= 2, true);
  assert.match(route, /\.eq\(\s*["']status["']\s*,\s*["']draft["']\s*\)/);
  assert.match(route, /\.eq\(\s*["']owner_id["']\s*,/);
  for (const term of ['bonus_library_owners', 'library_items', 'auth.getUser()',
    '"bonus-generated"', 'upsert: false', '@/lib/supabase/server']) {
    assert.ok(route.replaceAll("'", '"').includes(term), term);
  }
  assert.doesNotMatch(route, /SERVICE_ROLE|service_role|supabase-js/i);
});
