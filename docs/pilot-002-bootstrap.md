# Pilot 002: one paused task initialization

Task and provider budget are approved. Live execution and permission expansion
are not. The existing task remains RELEASE_READY version 16; it must never be
reset for this pilot. AWS read-only inspection on 2026-10-03 found the new task
absent and the controller disabled with logging-only access. The captured
controller template SHA-256 is
`9f8733a8f0b4644461ac8aba2399805b72fc2d6d6ccc5fba2eb32769ff91becf`.

## Next requested approval

Deploy the reviewed bootstrap package on the existing disabled controller, then
grant that role temporary GetItem and PutItem access to only
`FACTORY#tims-software-factory#TASK#safe-workspace-fingerprint-001` in
`tims-software-factory-state`, for at most one hour with an absolute expiry.
Enable concurrency one and invoke the pinned version once to atomically create:

- PAUSED task version 0 with no leases or consumed evidence.
- A permanent bootstrap marker binding source, contract and task/budget approval.
- One initialization audit record.

All three writes are conditional on absence. Existing, conflicting or partial
records stop the operation. An exact duplicate can be reconciled read-only;
uncertain outcomes must be investigated without reinvocation. SDK retries are
disabled. The 36-character transaction token is within DynamoDB's limit.

Then disable the function, restore zero concurrency and remove the temporary
policy. Preserve the old task, aliases, published versions, other functions,
all stack parameters and all historical ledgers. No signing or model call,
budget reservation, scheduler, provider credential access, candidate execution,
automatic PR merge or production release is part of this approval.

## Prepared implementation and operator checks

`scripts/build_pilot002_bootstrap_package.py OUTPUT.zip` builds a deterministic
small package from clean reviewed source, only the bootstrap handler, state
serialization and pinned contract/approval. It excludes provider integrations,
secrets and historical deployment approvals. Lambda supplies boto3; the handler
explicitly disables AWS SDK retries.

`scripts/prepare_pilot002_bootstrap.py INPUT.json OUTPUT.json` consumes the exact
live controller template, source commit, immutable S3 object version, nonce and
one-hour window. It emits disabled, active, restoration and rollback templates
without AWS calls. `validate_changes` checks actual change sets and parameters
against those exact templates before each execution. Reject source/package,
template, function role, handler, concurrency or permission drift. Publish a
version with the approved configuration and verify its code hash before the
single invocation; never move the acceptance alias.

At approval time, use a fresh one-hour window beginning then. Record its exact
timestamps before granting access; do not extend that window during a run.
Journal the invocation exclusively before sending it. Verify all three records,
unchanged old task, function shutdown and logging-only permissions afterward.
The next generation stage still needs candidate-bound provider requests, fresh
pricing and readiness, new per-role atomic attempt ledgers and reviewed access.
Existing fixed-candidate Builder/Inspector/QA entrypoints cannot be reused.

## Pricing/readiness limits

Published prices were rechecked on 2026-10-03: OpenAI GPT-5.6 Sol standard
short-context input/output is USD 4/20 per million tokens; Sonnet 4.5 global
inference is USD 3/15. These are planning observations, not reservations or
authorization, and must be refreshed and bound to exact requests before calls.
Google's prior successful call used unlinked free-tier billing. This bootstrap
does not assert current billing status, model access or the paid thinking/output
bound; it does not link billing or enable paid fallback. None of the three
provider routes is qualified for the new task merely by initializing it.

Sources:
- https://developers.openai.com/api/docs/pricing
- https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-sonnet-4-5.html
- https://aws.amazon.com/jp/blogs/news/amazon-bedrock-now-supports-japan-cross-region-inference/
- https://ai.google.dev/gemini-api/docs/pricing
