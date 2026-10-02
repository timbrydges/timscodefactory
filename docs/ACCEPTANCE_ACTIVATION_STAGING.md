# Acceptance activation preparation

`scripts/prepare_acceptance_activation_bundle.py BINDING.json JOB.json OUT.json`
prepares matching broker, Builder and controller environment updates and an
exact controller IAM policy. It performs no AWS IO, publishes no object,
signs no receipt, changes no contract gate and authorizes no model call.
All three execution flags in the output remain `false`.

The binding has exactly these fields:

- `activation_id`, `source_commit`, `contract_digest`, `starts_at`, `expires_at`
- `builder_version_arn`, `broker_version_arn` (numeric immutable versions)
- `job_version_id` (published immutable version, not `NOT_PUBLISHED`)
- `provider_secret_arn` (the exact acceptance secret ARN, never its value)

Supply the exact bytes of the published job. The existing controller decoder
checks its digest, source and receipt pins. The publication validator also
checks current owner/reviewer receipt expiry, accepted scope, lease expiry and
exact task input and contract. The activation must end before the pricing
quote expires. Pending operating-contract gates appear as blockers; preparation
does not clear them or make an inactive contract active.

The output is a preparation artifact, not a deployable authorization. Its
`environment_updates` must be merged with the existing role environment,
preserving signing and other reviewed settings. No deployment command is
provided by this tool. A subsequent guarded deployment must verify the actual
S3 versions and signatures, durable task state, unused activation budget,
artifact/source bindings, IAM and disabled schedule. Local version names alone
are not evidence that those objects exist. The output file is created only if
all preparation checks pass and is never overwritten.

Freeze the operational candidate before requesting an independently authorized
Inspector review. A review of an older commit or expired scope cannot authorize
a new candidate. Consumed Inspector activations must never be reset or retried.

## Guarded disabled configuration deployment

`scripts/stage_disabled_acceptance_config.py prepare COMPONENT BINDING JOB PLAN`
rebuilds the bundle and prepares one CloudFormation change set for `broker`,
`builder` or `controller`. `execute PLAN` permits exactly one in-place function
environment change, with all existing code, IAM, parameters, published versions
and the controller alias preserved. It checks the disabled no-retry schedule,
source checkout, template, runtime settings and revision again before execution.
The prepared template is compared with the actual AWS change set before use.

For binding stages, preparation and execution each read both pinned receipts,
verify their real signatures, check the authoritative unleased task and unused
budget, and read the exact published job version with its checksum. Changed,
forged or expired scope fails before any cloud configuration mutation. Canary
stages carry no activation binding and do not require scope receipts.

The staging command never signs receipts, grants permissions, publishes a
Lambda version, changes an alias, enables a schedule or invokes a function.
It updates only the unpublished function configuration. Deployed source matching,
IAM and all final activation gates remain required before live activation;
staging verification does not authorize execution or reserve provider spend.

An uncertain execution is saved as attempted before the AWS request. Use
`reconcile PLAN` to read the result; never retry `execute`. Reconciliation and
`verify PLAN` remain read-only even after receipt expiry. Plans cannot be
overwritten during preparation. Subsequent code-deployment tools deliberately
reject the staged template until that configuration is explicitly accounted for.

The model-free staging canary requires no job or receipt:

```text
python scripts/stage_disabled_acceptance_config.py prepare-canary controller CANARY_PLAN
python scripts/stage_disabled_acceptance_config.py execute CANARY_PLAN
python scripts/stage_disabled_acceptance_config.py prepare-cleanup CANARY_PLAN CLEANUP_PLAN
python scripts/stage_disabled_acceptance_config.py execute CLEANUP_PLAN
```

It adds only an inert `FACTORY_CONFIGURATION_CANARY` marker, verifies the
environment-only update, then removes exactly that marker with the same guard.
Published runtime versions and the acceptance alias must remain unchanged
through both steps. A canary is deployment-mechanism evidence, not a substitute
for paid scope review, signed receipts or final activation verification.

## Owner receipt publication

The `factory-owner-signing` workflow has a separate `publish_owner_receipt` job.
It remains disabled unless `FACTORY_OWNER_RECEIPT_PUBLICATION_ENABLED` is exactly
`true`. It requires the owner actor on `main`, the first workflow attempt, the
exact plan encoded as base64 and a separate owner-approved `sha256:` plan digest.
Inputs reach Python through environment variables, not shell interpolation.

`publish_acceptance_owner_receipt.py` rejects a changed source, task, scope,
lease, digest, price window or signer identity before signing. It uses the
enrolled non-exportable owner KMS key and writes only the owner's encrypted,
checksum-bound, immutable receipt with `IfNoneMatch: *`. It cannot generate an
Inspector approval or enable execution. No model call is made. Both workflow
reruns and client retries are disabled; an uncertain result must be reconciled
by reading the exact receipt key and verifying its signature before proceeding.
An attempt record is retained as a workflow artifact even when publication fails.

Do not enable or dispatch this job with a stale or placeholder plan. Prepare the
final candidate and exact scope first. A signed owner receipt is only one input
to the later guarded activation, and does not clear the operating-contract gates.

## Signed execution-job publication

`publish_acceptance_job.py verify BINDING PLAN RECEIPT_VERSIONS OUT` verifies
the current clean source, fixed acceptance input/contract, fresh receipt and
pricing windows, authoritative unleased task version, and unused activation
budget. It reads only the two pinned S3 receipt versions and verifies their
owner and independent Inspector signatures against the trusted key registry.
The supplied version names or an `ACCEPTED` field alone cannot pass this gate.
Verification performs no cloud writes.

`publish_acceptance_job.py publish BINDING PLAN RECEIPT_VERSIONS ATTEMPT` repeats
those checks and uploads exactly one encrypted, checksum-bound job to
`factory-autonomy-jobs/<activation_id>/IMPLEMENTATION.json`. It uses an exclusive
local attempt record, a conditional `IfNoneMatch: *` S3 write, and no client
retries. The returned immutable version and stored bytes are checked before
reporting publication. The job digest and version can then be supplied to the
activation-bundle preparer with the identical bytes from the offline job encoder.

If the upload response is lost, `publish_acceptance_job.py reconcile ATTEMPT`
only reads the object and matches its complete bytes, checksum and immutable
version to the attempted job. It never uploads again. Reconciliation proves
publication, not current authorization; final activation must recheck receipt
expiry, state, budget, source, IAM and runtime settings. None of these commands
reserve provider spend, change task state, sign receipts, invoke a role, grant
IAM, enable execution or clear any operating-contract gate.

## Owner-authorized first-run commissioning

The owner approved the bounded commissioning exception with “I approve!” on
2026-10-02 at 03:01:53 UTC. Its absolute expiry is 2026-10-03 at 03:01:53 UTC.
The checked-in contract records this authority; runtime execution remains disabled.

The remaining three gates are live activation proofs. Requiring them to be
complete before allowing the first activation creates a startup dependency.
`GUARDED_COMMISSIONING` provides an explicit owner-authorized exception for one
named activation, `factory-acceptance-commissioning-001`, while keeping all three
gates pending. It does not claim that the Factory is fully active or accepted.

The owner decision permits only the existing private
`deterministic-text-fingerprint` acceptance task: at most three GPT-5.6-Sol calls,
at most USD 0.25 each (USD 0.75 total reserved exposure), within the existing
USD 5 ceiling, for at most 24 hours from the recorded authorization. Fresh
pricing, receipt expiry and the activation window can shorten that period.
There are no retries or remediation cycles and no production-release authority.
Inspector reviews remain a separate budget. Inspector 008 accepted once; the
commissioning 001 delivery stopped before dispatch on a timestamp inconsistency.
Neither attempt may be replayed.

The actual approval is recorded in
`factory/evidence/guarded-commissioning-authorization.json`. The contract selects
`GUARDED_COMMISSIONING` and sets the three execution authority fields to
`ALLOW_GUARDED_COMMISSIONING`. Missing evidence, changed bounds, another
activation, or a changed list of pending gates fails closed. The authorization
must be packaged with the reviewed runtime, and its absolute expiry cannot be
extended by restarting or using another activation ID.

On 2026-10-02 at 12:19:52 UTC the owner approved safe task recovery, one fresh
Inspector 009 review (USD 0.25 cap, USD 0.24144 reservation, no retries), and one
new commissioning attempt under the same three-call/USD 0.75 bounds and original
2026-10-03 03:01:53 UTC expiry. The selected commissioning evidence is now
`factory/evidence/guarded-commissioning-002-authorization.json`, for
`factory-acceptance-commissioning-002`; the original evidence remains intact.
This approval does not reset a budget, extend expiry, or authorize production.

The new capability identifier equals the new commissioning activation ID, so
fresh signatures cannot collide with the immutable approval from attempt 001.
Preparation rejects an existing capability before any Inspector call. Publication
and staging retain expired or revoked lease history, reject active leases, and
reject reuse of the new plan's lease ID. Recovery never erases old approvals,
leases, dispatch records, or provider reservations.

Both fresh scope signatures, exact code/job/role versions, reviewed IAM,
disabled-first deployment, the durable unused budget and task state remain
required. The per-effect runtime and no-retry guards are unchanged. Generic
provider qualification and production release cannot use commissioning authority.
All execution switches remain off until the separate guarded deployment steps
pass; this authorization does not supply live gate evidence or itself enable a schedule.

## Guarded publication and one scheduled delivery

`activate_acceptance_component.py` publishes broker, Builder, then controller.
Each stage requires the actual fresh owner and Inspector signatures, immutable
published job, unchanged unleased task, absent activation budget, current source
artifact and exact IAM. All three components must use the same package bytes.
Predecessor journals bind numeric versions and their complete configurations.
Builder IAM is repinned to the newly published broker; controller IAM is limited
to the task, activation budget, immutable job/receipt versions and Builder.
Changing the version Description forces configuration-only Lambda publication.
The controller alias receives explicit zero asynchronous retries and a 60-second
event-age bound. Every component step leaves the schedule disabled.

`activate_acceptance_schedule.py` rechecks the complete chain and fresh scope,
then changes the existing disabled schedule to one UTC `at(...)` delivery.
This commissioning run does not turn on recurring operation. The scheduled time
must leave at least five minutes before every scope deadline. Both Scheduler and
Lambda have zero configured retries; durable dispatch and budget guards remain
necessary because delivery is not an exactly-once guarantee. The schedule is
retained after completion for read-only reconciliation. Its delivery result,
durable dispatch, task and budget must be inspected before claiming success.

All mutations persist an attempt before submission. An unknown result must be
reconciled read-only; never re-submit or manually invoke the controller to
compensate. No tool signs scope, resets budgets, retries a provider, clears live
gates, or grants production-release authority.

Commissioning 002 delivered once on 2026-10-02 at 13:23:06 UTC after Inspector
009 accepted. It reached Builder and the provider broker but stopped on an HTTP
failure, leaving dispatch STARTED and one USD 0.25 reservation. The old adapter
did not retain the numeric HTTP status; actual provider cost remains unknown.
The schedule was disabled and the runtime quarantined. See
`factory/evidence/inspector-009-and-commissioning-002-outcome-2026-10-02.json`.
Neither the dispatch nor Inspector 009 may be retried. Future HTTP failures
report only a validated numeric status, never upstream bodies or credentials.

The owner approved fresh Inspector 010 and commissioning 003 on 2026-10-02
at 13:45:56 UTC, retaining the same USD 0.25 Inspector cap, USD 0.24144
Inspector reservation, three-call/USD 0.75 commissioning bound, overall USD 5
ceiling and original expiry. The selected evidence is
`factory/evidence/guarded-commissioning-003-authorization.json`.
Wait for the existing lease to expire before preparing the fresh live review;
do not revoke it early, erase history, reset reservations or replay attempt 002.
Fresh signatures and all deployment gates remain required; no pending live gate
is claimed complete and production release remains prohibited.

Inspector 010 passed; commissioning 003 stopped after one provider HTTP 401.
Its reservation and STARTED dispatch remain preserved, with zero retries.
See `factory/evidence/inspector-010-and-commissioning-003-outcome-2026-10-02.json`.
After replacement credential installation, the owner approved Inspector 011
and commissioning 004 at 2026-10-02T14:59:18Z with the same per-call caps,
three-call commissioning bound, overall USD 5 ceiling and original expiry.
Wait for the existing lease to expire naturally; fresh signatures and all
deployment gates remain required. No production release is authorized.

Commissioning 004 authenticated successfully and recorded one provider response
for USD 0.003045 (conservative accounted cost). It advanced to INSPECTION v6,
but the response only requested missing context and contained no implementation.
This is transport success, not acceptance success. Preserve its signed receipt,
four leases, completed broker claim and USD 0.25 reservation without replay.

The Builder now receives the immutable contract and the source snapshot at
`fcb4c535d4ea00962b26db14f59e34917ef2389f`, where both allowed paths are absent.
Before signing a successful Builder receipt, require one JSON source package
with exactly `fingerprint.py` and `tests/test_fingerprint.py`, both nonempty and
syntactically valid Python. This check does not execute model code or establish
functional correctness. The exact candidate still requires isolated tests and
independent inspection bound to its commit. Recheck the acceptance repository
base before applying any future candidate; never overwrite a changed base.

The current INSPECTION state must not be treated as evidence of a code artifact.
No automated remediation is authorized. A fresh owner-approved recovery scope
and signed state transition are required before another implementation attempt;
do not reset budgets, erase history, revoke leases early or replay 004.

## Owner-approved recovery 005 (2026-10-02)

The owner separately approved exactly one recovery cycle at 15:41:07Z,
Inspector 012 (one call, USD 0.25 maximum, USD 0.24144 reservation) and
commissioning 005 (up to three calls, USD 0.75 total). Zero retries, the
USD 5 overall ceiling, original 2026-10-03T03:01:53Z expiry, and no production
release remain binding. This supersedes the preceding zero-remediation limit
only for this exact recovery. Historical authorizations remain unchanged.

`recover_acceptance_missing_artifact.py NEW_JOURNAL.json` requires the exact
INSPECTION v6 receipt and four already-revoked leases, disabled components
and schedule, fresh pricing and authorization. It records an atomic owner
override to IMPLEMENTATION v7, preserving consumed evidence and lease history.
A new exclusive journal and state-version guard prevent replay. It makes no
provider call and cannot recover any later failure. Fresh Inspector and owner
signatures are required before commissioning 005.

## Commissioning 005 timeout and bounded generation settings

Inspector 012 accepted in one call (USD 0.016284). The authorized owner
recovery committed IMPLEMENTATION v7 without erasing history. Commissioning
005 reserved one USD 0.25 call and issued a fifth lease, reaching v8. Its
provider adapter timed out at 60 seconds with no completed response stored.
Actual provider cost is unknown; retain the full reservation and STARTED
dispatch/claim. No successful artifact receipt or implementation exists.
The recovery cycle is consumed. Never repeat 012 or 005, reset their budgets,
or reuse their signatures. A new paid scope requires separate owner approval.

Acceptance-only generation now explicitly uses low reasoning effort and a
90-second deadline, leaving 30 seconds inside the existing 120-second broker
Lambda limit. Token, price, no-retry, credential and artifact limits remain
unchanged. This is a tested configuration mitigation, not a verified live
provider success. Deploy it disabled; no new provider call is authorized here.

## Fresh Inspector 013 / single-call commissioning 006

Owner approval recorded at 2026-10-02T16:26:54Z authorizes one Inspector call
(maximum USD 0.25; reservation USD 0.24144) and exactly one Builder call
(maximum/reservation USD 0.25), only after the existing lease expires at
2026-10-02T16:58:20Z. Preserve the authoritative IMPLEMENTATION v8 state and
five leases; no additional owner recovery, budget reset or prior-call replay.

Commissioning 006 narrows the effective allowance and atomic DynamoDB budget
to one call and USD 0.25. Immutable original financial evidence and acceptance
contract remain unchanged. The overall USD 5 cap and 2026-10-03T03:01:53Z
expiry remain binding. Retained reservations USD 4.37872 plus the new pair
USD 0.49144 total USD 4.87016. Fresh Inspector and owner signatures, clean
source pins, current pricing, disabled-deployment proofs and zero retries
remain required. This authorization does not claim implementation success.

## Commissioning 006 artifact and pending implementation review

Inspector 013 accepted the preimplementation scope in one call (USD
0.017514). Commissioning 006 then returned the two allowlisted files in one
Builder call (USD 0.042565), recorded its receipt, and reached INSPECTION v10
with all six leases preserved. The low-reasoning, 90-second provider settings
have now produced a live artifact. Prior timeout claims remain untouched.

The exact Builder bytes are candidate commit
`09a758184c890eda200326a18fb166641194e32e` in acceptance-repository draft PR #2.
All 11 required unit tests and 14 independent local behavior checks passed;
the Python 3.12 GitHub test gate also passed on that exact commit. The pending
implementation-inspection evidence packet binds the code, contract, hashes,
and validation results. It authorizes no model call and supplies no verdict.

The separate independent Inspector must still rerun required tests and bind
its verdict to the candidate commit. Do not merge or claim completed Factory
acceptance from the scope review or tests alone. No production release is
authorized. All component execution flags and the schedule were verified
disabled after delivery; temporary concurrency quarantines were removed.

Preserved reservations total USD 4.87016, leaving USD 0.12984 under the
unchanged USD 5 cap. Another standard USD 0.24144 Inspector reservation would
raise that total to USD 5.11160 and therefore requires separate owner approval
for the call and a sufficient overall cap. No budget or state reset, prior-call
retry, new Builder call, or expiry extension is authorized by this evidence.

## Independent implementation Inspector 014

The owner approved one separate Inspector call for Builder candidate
`09a758184c890eda200326a18fb166641194e32e`, maximum USD 0.25 and reservation
USD 0.24144, with no retries. The separate overall cap is USD 5.25; all prior
reservations remain held (USD 4.87016 before this call, USD 5.11160 after).
The original expiry remains 2026-10-03T03:01:53Z. No new Builder call, state
reset, schedule activation, or production release is authorized.

The disabled Inspector has a separate implementation-review event. It accepts
only the exact bundled packet and manually inspected source hashes, reruns the
11 required tests in Python 3.12 with an isolated temporary directory and
credential-free subprocess environment, then reserves 014 before one Bedrock
call. Test failure spends nothing; uncertain provider outcomes consume the
reservation. Its signed evidence binds the candidate commit, file hashes,
actual test output, and model assessment. It is not a scope-review receipt and
cannot authorize dispatch or release. No general-purpose code runner exists.

`invoke_implementation_inspector.py` requires the exact clean deployed package,
INSPECTION v10 with six preserved leases, the completed Builder claim, all
execution flags and schedule disabled, and USD 4.87016 prior reservations.
It journals the attempt before invoking an exact Inspector version and verifies
the returned signature and evidence hashes. An existing output directory or
budget record blocks replay. Preserve the result even on failure.
