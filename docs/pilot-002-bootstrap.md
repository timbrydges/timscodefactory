# Pilot 002: one paused task initialization

Status on 2026-10-03: the owner approved the reserved-one bootstrap, but AWS
rolled back activation before any Lambda invocation. The account limit is 10
and AWS's error requires at least 10 unreserved executions, so reserving one
is unavailable. The original deployment is restored, concurrency is zero,
the enable flag is false and only the logging policy remains. The new task is
still absent and the old task remains RELEASE_READY v16. No model call or
budget reservation occurred. Evidence:
`factory/evidence/pilot-002-contained-failure-2026-10-03.json`.

## Revised capacity decision requested

Approve using the existing shared account pool for this same one-time
initialization, without increasing AWS quotas. The regional pool currently
permits at most 10 concurrent executions; the function would temporarily have
no dedicated per-function reservation. Verify that both total and unreserved
account concurrency still equal 10 before activation. This changes the capacity
control, so the earlier reserved-one approval is not treated as permission for it.

Keep the same task-only GetItem/PutItem policy, one operator invocation, no
automatic retries and a fresh window of at most one hour starting after this
revised approval. Atomically conditioned state, permanent marker and audit
creation still admit only one successful initialization, including concurrent
duplicate requests. Existing or partial state cannot be overwritten. A racing
transaction regression test exercises this protection. No model, secret,
signing, scheduling, release, existing-task or budget-ledger access is added.

After the attempt, restore reserved concurrency zero and remove the temporary
policy. Preserve operation-001's failed-deployment journal; no initialization
invocation was made there. Use a new operation journal and new grant/restore
change sets for the revised mode, not the consumed failed change set. Do not
extend the new access window during execution. The bootstrap runtime package
from source `0813cf8ce6106dcf0815fd8cd80fd2ca19267873` is unchanged.

The preparation helper's default remains `reserved-one`. The explicit
`capacity_mode="shared-account-pool"` emits only a pending proposal, never live
approval. It accepts the already-disabled bootstrap controller as a safe
baseline so a fresh approval window can be prepared without resetting history.

Task and provider budget are approved. Live execution and permission expansion
are not. The existing task remains RELEASE_READY version 16; it must never be
reset for this pilot. AWS read-only inspection on 2026-10-03 found the new task
absent and the controller disabled with logging-only access. The captured
controller template SHA-256 is
`9f8733a8f0b4644461ac8aba2399805b72fc2d6d6ccc5fba2eb32769ff91becf`.

## Original reserved-one operation scope

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
