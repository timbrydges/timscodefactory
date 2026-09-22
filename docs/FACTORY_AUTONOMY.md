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
signatures. See `docs/FACTORY_CLOUD_ROLES.md` for evidence limits and deployment
requirements. Cloud functions, scoped execution permissions and concrete model
backends are not deployed. No model allowance or autonomous scheduling is enabled.


### Role deployment package prepared — 2026-09-22

The three Lambda identity-probe packages, separate execution-table IAM boundary,
exact signing-role trust update and owner CloudShell preparation/execution/verification
scripts are prepared. Operational backend calls remain disabled. The agent AWS
browser is unavailable; no Lambda deployment is claimed without the resulting
cloud evidence. Details: `docs/FACTORY_CLOUD_ROLES.md`.
