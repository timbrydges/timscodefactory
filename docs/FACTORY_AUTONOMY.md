# Completing Tim's Software Factory

The priority is a reusable autonomous software delivery service. Bonus Library
is the acceptance project; further product features should serve a named Factory
milestone. AI-generated product descriptions are not Factory worker calls.

## Current evidence, 2026-09-22

- Cloud identities, authoritative DynamoDB state, immutable release storage and
  rollback were verified: `factory/evidence/controller-deployment-2026-09-13.json`,
  `aws-bootstrap-2026-09-13.json` and `aws-rollback-drill-2026-09-13.json`.
- The original Planner → Builder → independent Inspector pilot shipped and
  recovered an artifact. It retired with an explicit budget-history exception;
  replacement cumulative budget controls passed live verification. See
  `factory/evidence/pilot-closeout-2026-09-17.json`.
- Runtime sandbox, bounded repair and liveness components exist. Their presence
  does not prove a continuously operating end-to-end worker.
- `.github/workflows/controller-runtime.yml` provides bounded manual verification
  modes, not a reusable scheduler. The retired pilot must not be reactivated by changing
  its status labels. Bonus Library's contract still denies operational role
  activation, even though the product itself is live.

## Completion milestones

| Milestone | Completion evidence | Status |
| --- | --- | --- |
| Durable dispatch | One claim under contention; crash cannot duplicate a provider call; paused/stale work rejected | Signed-scope and claim mechanics verified live in run 35663169496; integrated worker proof below |
| Cloud worker | Approved task intake → claimed job → independently identified role → persisted result, survives worker restart | Worker integration verified live in run 35673170867; real adapters and continuous activation pending |
| Automatic progression | Planner → Builder → Inspector → QA/security; bounded repairs; exact source/evidence binding; cumulative budget before every call | Components exist; integrated project run pending |
| Owner controls | Visible queue, progress, spend, failure reason; pause/stop/resume; clear release request | End-to-end operator interface pending |
| Acceptance and operation | Approved project runs with chat closed, two-worker contention and crash/pause tests, release authorization and rollback | Pending |

Tim remains the sole production release authority and can intervene at any time.
Routine work within an approved task should advance without repeated “proceed”.
A task that reaches a budget, permission, scope or uncertain-outcome boundary
stops with a concrete reason; it does not silently acquire new authority.

## First implementation: durable dispatch ledger

`src/factory_state/dispatch.py` stores a dispatch under the existing task partition.
It requires a persisted, active role lease and the exact current state payload
and version. The record binds the source commit, contract digest and input digest.
A task lease can name only one job, even when a worker changes its input or commit.

The worker sequence is:

1. Load authoritative state and validate the current owner-approved project
   contract, activation, role identity and configured time limits.
2. Enqueue the role request conditionally; on a duplicate or lost response,
   read the same lease record and reject changed bindings.
3. Claim READY → STARTED with a conditional transaction that rechecks state.
   Only the successful claimant may attempt external dispatch.
4. Before every model call, atomically reserve the existing cumulative budget
   and attempt allowance. The ledger itself grants no spending authorization.
5. Record the result receipt digest under that worker's claim. The controller
   separately verifies signed evidence and uses the existing state machine to
   advance; receipt storage is never approval.

A restart can read READY work and claim it. STARTED without a receipt is an
**unknown external outcome**: reconcile against the external job's stable ID or
escalate. Never expire/reclaim that record and blindly invoke the provider again.
A late receipt after pause is retained for audit but cannot resume the task.
Production release roles are excluded from this generic dispatcher and must use
`release_control.py` and Tim's exact-commit authorization.

This change does not deploy a worker, grant IAM rights, enable schedules, activate
roles, change project contracts, or spend provider budget. Next: a model-free
DynamoDB contention/crash canary, then a concrete bounded cloud-worker activation
proposal with its own task allowance. The Bonus Library description test's US$1
allowance must not be reused as Factory agent funding.

## Objective enforcement at dispatch

Tim's Software Factory has always been the deliverable. Bonus Library is only a
replaceable test fixture; feature shipping there does not itself count as Factory
progress. This rule also applies to manual work directed through chat.

Every proposed task must name an unfinished Factory capability, the evidence it
will produce, and a stop criterion. A reviewer must examine that connection, not
accept a capability label as proof. Examples:

- Proving independent Builder/Inspector identities on a bounded test change is
  relevant to Factory autonomy.
- Polishing a Bonus Library cover, marketing description or product workflow is
  out of scope unless a concrete unfinished Factory acceptance test requires it.
- Once the required evidence is accepted, mark the capability complete; a generic
  “proceed” does not authorize extending the fixture or reopening that capability.

The dispatch ledger now requires two persisted scope records in the same atomic
transaction as enqueue and claim:

1. `FACTORY#<factory>#TASK#SCOPE#OBJECTIVE#<objective>` / `CAPABILITY#<capability>` with
   `status=OPEN`, `owner_identity=tim_brydges`, and the exact `contract_digest`.
2. The task partition's `SCOPE#<lease>` record with `status=ACCEPTED`, the exact
   serialized dispatch `binding`, a `review_evidence_digest`, and an independently
   authenticated `independent_inspector_service` or `product_spec_reviewer_service`
   identity different from the executing lease identity.

Missing, closed, changed-contract, withdrawn-review and mismatched-input records
fail the transaction. A capability closed after enqueue blocks a later claim.
Scope identities are immutable parts of the request binding; changing them cannot
create another job under the same lease. Existing queued requests without scope
fields need fresh review, not an automatic default or migration approval.

These rows are trusted controller records, not agent-supplied approval flags.
Before live use, the controller adapter must validate owner authorization and
signed independent review evidence before writing them, restrict agents from
writing them, and bind capability completion to accepted evidence. The signed writer below supplies signature verification; production signer
enrollment and authenticated adapters remain prerequisites. The consumer gate
fails closed when required records are absent.

Closure blocks future claims; it cannot undo an external operation already
started. The worker must recheck activation before external effects and reconcile
in-flight jobs under the existing pause/termination policy. Budget reservation,
role activation, source review, and Tim's release authorization remain separate.

Progress reports must state the Factory capability, evidence, remaining blocker,
and next action. Count accepted capabilities, not product features or commits.

## Signed scope writer and model-free cloud verification

`SignedScopeStore` verifies canonical JSON with Ed25519 signatures using OpenSSL
before writing immutable capability and task-review records. Trusted public keys
come from controller configuration, never job input. Binding, rationale, evidence
and stop criteria, signer separation, freshness and replay are checked. Dispatch
also checks persisted approval expiry atomically at enqueue and claim.

The reserved objective namespace is under `TASK#SCOPE#OBJECTIVE#`; a normal task
identifier cannot contain `#`. This fits the controller's existing IAM partition
allowlist without adding cloud rights. The earlier unactivated objective prefix
is superseded; no production data migration is needed.

The `controller-runtime` workflow has a Tim-only `scope-canary` mode on main.
Its session policy confines writes to two run-specific fixture partitions and
explicitly denies Bedrock. It uses ephemeral synthetic owner/reviewer keys to
verify signature mechanics, missing/replayed/tampered approvals, closure after
queueing, duplicate claims and idempotent receipts. It closes the capability and
pauses the fixture at completion; it never deletes evidence.

Synthetic signatures are NOT proof of actual independent agent review, owner
key enrollment, or a continuously running worker. Production key provisioning,
authenticated signing adapters and worker integration remain required. The
canary is model-free and creates no production deployment. Unexpected failures
abort rather than being counted as successful conditional rejection.

### Live verification — 2026-09-21

PR112 merged as `94e9ca52859fb07b21879a1bba9353e7898e5f09`.
[Controller run 35663169496](https://github.com/timbrydges/timscodefactory/actions/runs/35663169496)
succeeded against AWS DynamoDB with all 12 signed-scope and dispatch checks.
The run made zero model calls and zero production deployments, then closed its
capability and paused its task. Durable evidence is in
`factory/evidence/scope-dispatch-canary-2026-09-21.json`.

This closes live verification of the signed-record dispatch mechanics. It does
not close autonomous operation: production signer enrollment, authenticated
review adapters, and the continuously running worker remain unfinished. The next
Factory capability is connecting those real identities and worker execution to
these verified gates. Bonus Library remains only a test project.

## Bounded worker integration — 2026-09-22

`DispatchWorker` consumes an existing READY record under an authenticated
controller adapter. It checks exact deployed source and actual input/contract
bytes, reverifies retained scope signatures using current trusted keys, checks
role activation, claims once, and requires the adapter to reserve its cumulative
budget before execution. It rechecks activation, signatures, state and scope
before calling the role adapter. It verifies a role-signed result bound to the
exact dispatch and output bytes, then atomically stores payload, signature,
output and receipt. It never advances a gate or dispatches a release.

A restarted worker returns the existing receipt or NEEDS_RECONCILIATION for
STARTED work; neither repeats the external call. A claim error is propagated,
not assumed to be a safe retry. Invalid/expired result signatures leave STARTED
for reconciliation. Late valid results remain audit records and cannot resume a
paused task. The role adapter must also enforce pause, credential and budget
checks at each external effect; a database guard cannot make a remote call atomic.

Scope records now retain signatures. Earlier rows without signatures are denied
by the worker; they require new reviewed leases/records, not an unsigned fallback.
`scope-signers.json` now contains the four live-verified public keys approved by
Tim on 2026-09-22. Their initial enrollment expires on 2026-12-21 UTC. `load_trusted_signers` validates exact Ed25519 material,
fingerprints, distinct keys, enrollment-commit references, activation windows and
revocation. The path is controller deployment configuration, never task input.
The enrollment commit must actually be reviewed for identity/key custody; a hash
shaped string alone is not proof. Private keys must stay with their respective
owner/role signer, outside the controller and repository.

`worker-canary` exercises deterministic fixture execution, signed result
retention, completed-work restart, lost response, wrong signer, revoked reviewer,
and pause after reservation against the same two isolated AWS partitions. All
signers are synthetic. It neither enrolls real identities nor enables a scheduler.

### Remaining activation inputs

- Public-key enrollment is complete for the four isolated KMS roles. Preserve
  their custody boundary when deploying role services and propagate registry
  revocations to those deployments. GitHub App IDs alone are not signing proof.
- Deploy authenticated executor/reviewer transports. A Python identity property
  is not authentication; the controller must not run untrusted agent code in its
  own process or expose its DynamoDB credentials to a role.
- Approve a fresh bounded Factory operating contract and provider allowance;
  the retired pilot and Bonus Library description allowance do not authorize it.
- Wire the scheduler/intake and result-to-state evidence adapter, then verify a
  complete independently reviewed run while chat is closed.

### Live worker evidence

[Run 35673170867](https://github.com/timbrydges/timscodefactory/actions/runs/35673170867)
passed all eight worker checks at source
`0fdad0d528eb577e611abfd4ec5f2846e2cc3c9f`. Safe evidence is retained in
`factory/evidence/worker-integration-2026-09-22.json`. The initial import failure
was corrected with the existing hash-locked runtime dependencies. Local validation
passed 450 tests; PR CI also passed the real Docker and HTTP/TLS broker checks.

The proven milestone is bounded dispatch-to-signed-result worker mechanics in
AWS, including restart, lost response, signer revocation and pause enforcement.
Real identity custody was subsequently verified in PR #119. Remote role execution
and unattended scheduling remain unfinished. No model calls or production
deployments occurred during the worker verification.

### Real signer deployment and enrollment — 2026-09-22

The four-role KMS deployment and real signing adapter are prepared in
`docs/FACTORY_SIGNING_DEPLOYMENT.md`. The deployment adds four independently
permissioned, non-exportable Ed25519 keys with separate GitHub OIDC workflows.
Tim approved the new US$4/month key-storage charge plus metered requests on
2026-09-22; see the signing deployment authorization audit.
Tim deployed the stack and all four identity workflows passed: four valid
signatures and twelve cross-role signing denials. PR #119 retains public proof
and artifact digests. The canary switch is confirmed false.

Tim then approved enrollment of those exact keys. The public-key registry and
exact KMS ARN bindings now reference verified evidence commit
`1fb5b37106bdf2a29defa0d95d0bc657dfcc9ab5`, with a 90-day validity window.
`EnrolledKmsReceiptSigner` connects role-side signing to that registry and rejects
revoked, expired, disabled or mismatched enrollment before signing. This completes
key enrollment and the signing configuration boundary; it does not deploy
remote AI role services or prove autonomous operation.


### Cloud role transport implemented — 2026-09-22

`LambdaRoleExecutor` and `RoleExecutionService` now implement the controller-to-role
boundary, including exact function versions, bounded synchronous responses,
role-side durable claims, signed results and duplicate/lost-response handling.
All three roles pass the local integration checks with simulated AWS and real
signatures. The model-free `transport_canary` was then deployed from
`4faff65894a2d95286f3d657e84972ff37a09b03` and verified for all three exact
version `:2` functions: signed responses, identical replay and durable `COMPLETE`
records passed with zero model calls. Concrete model backends and autonomous
scheduling remain disabled. See `docs/FACTORY_CLOUD_ROLES.md`.


### Role deployment package prepared — 2026-09-22

The three Lambda identity-probe packages, separate execution-table IAM boundary,
exact signing-role trust update and owner CloudShell preparation/execution/verification
scripts are prepared. Operational backend calls remain disabled. The agent AWS
browser is unavailable; no Lambda deployment is claimed without the resulting
cloud evidence. Details: `docs/FACTORY_CLOUD_ROLES.md`.

### Signed-result progression adapter — 2026-09-22

`SignedResultProgressor` closes the controller-side result-to-state gap. It reads
only a retained `RECEIPT_RECORDED` dispatch, revalidates the exact payload,
output digest, role signature and still-active signed owner/reviewer scope, then
persists one evidence-backed state transition through the authoritative state
store. Replays return the already-consumed evidence without another write.

The deterministic map covers Specification through Security Review and stops at
`RELEASE_READY`. It cannot issue leases, create approvals, invoke roles, retry an
unknown outcome, enable scheduling or dispatch production. Automatic intake,
next-role lease creation and the unattended scheduler remain separate work.

### Authenticated automatic intake — 2026-09-22

`AuthenticatedIntakeService` prepares a deterministic next-role lease and exact
dispatch binding for isolated owner and reviewer signatures. Activation verifies
both signatures before mutation, persists the lease, stores immutable scope and
queues one request. Re-entry after any completed boundary reuses the exact lease,
scope and queue instead of creating duplicate work.

Role selection is fixed by the current Factory stage. The service cannot create
signatures, choose an arbitrary role, invoke the worker, spend provider budget,
enable a schedule or queue release automation. The remaining autonomy boundary
is the authenticated owner/reviewer receipt transport followed by a disabled-by-
default scheduler that composes intake, worker and signed-result progression.

### Disabled autonomous cycle and immutable receipt transport — 2026-09-22

`VersionedS3ReceiptTransport` reads only the exact owner and reviewer object
versions under a plan-derived key in the existing versioned Factory bucket. The
envelopes bind the full intake plan, signer identity and signed payload; intake
still performs the cryptographic verification. Dynamic buckets, prefixes,
unversioned reads, SDK retries, oversized/duplicate JSON and changed bindings
are denied.

`AutonomousCycle` composes that transport with authenticated intake, one
`DispatchWorker` run and one `SignedResultProgressor` transition. It is disabled
unless explicitly constructed with `enabled=True`, performs at most one new role
invocation per step, and returns `NEEDS_RECONCILIATION` rather than repeating a
`STARTED` outcome. It cannot dispatch release automation and stops at
`RELEASE_READY`. No schedule, receipt-writing permissions or provider allowance
are deployed yet; those remain the final activation boundary.

### Bounded unattended scheduler — 2026-09-22

`AutonomousScheduler` adds the reusable scheduler-side tick without deploying a
schedule. Each tick is bound to one exact factory, task, source commit, contract
digest and time window. It rereads authoritative state, stops without loading job
material when the task is paused, stalled, terminal or `RELEASE_READY`, and may
compose at most one worker invocation. Any job-source binding change, multi-call
result or release assertion fails closed.

The scheduler and cycle each require separate explicit enablement. External
concurrency remains safe through the existing deterministic lease, conditional
dispatch claim and unknown-outcome reconciliation rules. This closes the local
unattended orchestration component; it does not approve a Factory operating
contract, provider spend, receipt-writing authority or an EventBridge/GitHub
schedule. Those live inputs still require exact owner-authorized deployment and
an independently reviewed acceptance run.

### Authenticated immutable receipt publication — 2026-09-23

`VersionedS3ReceiptPublisher` closes the application-side receipt-writing gap.
An isolated owner or reviewer signer can publish only its exact payload from one
prepared intake plan, under the plan-derived bucket key. The write uses canonical
JSON, a bound SHA-256 checksum, AES-256 storage encryption and `If-None-Match: *`;
success requires a concrete S3 object version. A wrong signer, unversioned result,
changed plan, oversized envelope or retry-enabled client fails closed.

The publisher does not grant S3 or KMS permission, choose work, approve scope,
enable the scheduler or authorize provider spend. The two roles still require
separate least-privilege deployment policies, and an uncertain write outcome must
be reconciled against S3 rather than blindly repeated.

### Owner-approved bounded operating allowance — 2026-09-23

Tim approved the first autonomous acceptance allowance: OpenAI `gpt-5.6-sol`,
USD 5.00 total, USD 0.25 per call, three calls maximum and a 24-hour maximum
window, with no production-release authority. The exact terms and owner event are
retained in `factory/autonomy/operating-contract.yaml` and its evidence record.

This is financial and scope authorization, not a claim that execution is live.
The contract remains default-deny while fresh pricing, ephemeral credential path, target switch,
operational role backends, receipt-writer IAM, disabled schedule canary and
independent pre-activation review remain pending. Code rejects `ACTIVE` while any
gate remains open or any approved financial/model/release term drifts.

### Exact private acceptance target — 2026-09-23

The isolated private repository `timbrydges/tims-factory-autonomy-acceptance`
(repository ID `1382496429`) now contains the immutable
`deterministic-text-fingerprint` task contract at commit
`fcb4c535d4ea00962b26db14f59e34917ef2389f`. The contract SHA-256 is
`7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa`.

The operating allowance and retained evidence bind the exact private repository,
task, commit, Git blob and content digest; any drift fails closed. This verifies
only the repository and task-definition gates. Provider calls, scheduling,
infrastructure changes and production release remain disabled.

The active `Factory acceptance main` ruleset (ID `23853140`) protects the
default branch with no bypass actors. It requires a pull request, an up-to-date
`test` status check, and blocks deletions and force-pushes. These controls are
also bound into the operating contract and evidence record.

### Official provider pricing reference — 2026-09-23

Official OpenAI documentation confirms that `gpt-5.6-sol` is available on the
Responses API with Standard short-context rates of USD 4.00 per million input
tokens and USD 20.00 per million output tokens. Long-context pricing begins
above 272,000 input tokens.

The operating contract binds a 42,020-byte conservative request ceiling and
4,096 output-token ceiling. Treating every request byte as one input token,
the maximum modeled Standard call cost is exactly USD 0.25000000. The live
adapter still recomputes the actual request bound before obtaining credentials.

This retained reference does not close the activation-time
`fresh_provider_pricing` gate. A quote no older than 86,400 seconds must still
be observed immediately before activation. No credential was created and no
provider call was made.

### Broker-only provider credential path prepared — 2026-09-23

The runtime now includes an AWS Secrets Manager credential source that reads
only the exact Factory OpenAI secret at `AWSCURRENT`, using a no-retry,
exact-region client, and exposes it only as a 300-second in-memory lease to the
provider adapter. Secret values are never represented in Terraform, evidence,
logs, or role payloads.

Terraform prepares a dedicated rotating KMS key, recoverable secret metadata,
and a standalone least-privilege reader policy restricted to the exact secret,
exact version stage, and KMS decryption through Secrets Manager in
`ca-central-1`. The policy is intentionally unattached until an isolated
provider-broker runtime role exists.

This closes only the implementation-preparation subgate. The
`ephemeral_provider_credential_path` activation gate remains open until the
secret, runtime role and policy are deployed and independently verified. No
credential was created and no provider call was made.

### Exact live-target authorization path prepared — 2026-09-23

The live qualification authorizer now binds the checked-in owner event to the
exact `coding_primary_sol_live` / `gpt-5.6-sol` pair. It independently requires
Tim's identity, the locked corpus digest, an exact source commit, a bounded spend
reservation, and matching enable switches in both the live policy and model
catalog. The unapproved challenger remains denied even if its switches drift on.

Both approved-target switches remain false. This closes only the authorization
implementation-preparation subgate; `approved_target_technical_enablement`
remains pending until an owner-reviewed activation commit deliberately changes
both switches after the other gates pass. No credential was requested, no
provider call was made, and production release remains denied.

### Operational backend boundary prepared — 2026-09-23

The role-side operational backend now re-loads the retained operating allowance
at every activation, reservation and execution boundary. It accepts only the
exact `deterministic-text-fingerprint` task, `coding_primary_sol_live` target,
`gpt-5.6-sol` model, activation source and contract digest. Its injected task
executor receives no provider credential, and requests remain bounded to 42,020
bytes, USD 0.25 per call and three calls.

The backend defaults disabled and the checked-in allowance still has pending
gates, so both controls independently deny execution. This closes only the
backend-boundary implementation subgate; `operational_role_backend_deployment`
remains pending until this boundary is composed into a fresh immutable Builder
Lambda version and independently verified. No operational backend was deployed,
no provider call was made, and production release remains denied.

### Least-privilege receipt-writer IAM prepared — 2026-09-23

Terraform now defines separate, unattached owner and independent-review writer
policies. Each permits only `s3:PutObject` to its exact receipt suffix beneath
`factory-scope-receipts/*/` and requires AES256 server-side encryption. Neither
policy grants reads, listing, deletion, version deletion, ACL changes, Factory
state access, release access, or cross-writer publication.

This closes only the IAM implementation-preparation subgate. The
`least_privilege_receipt_writer_iam` activation gate remains pending until the
policies are deployed, attached to separately verified publisher identities,
and canaried. No policy was attached, no receipt was published, and production
release remains denied.

### Disabled scheduler deployment and canary prepared — 2026-09-23

Terraform now contains an explicit opt-in for creating the acceptance schedule,
with the opt-in false by default and the deployed schedule hard-coded
`DISABLED`. Its service role can invoke only the exact acceptance Lambda alias,
is source-account and source-schedule bound, sends only the approved task
identity, retains events for at most 60 seconds, and performs zero retries.

A read-only canary verifies the schedule name, disabled state, cadence, target,
role, payload and retry limits without invoking or modifying it. This closes
only the implementation-preparation subgate; `disabled_schedule_deployment_and_canary`
remains pending until the operational backend exists, the disabled schedule is
deployed, and the canary passes in AWS. No schedule was deployed or enabled, no
provider call was made, and production release remains denied.
