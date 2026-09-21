# Completing Tim's Software Factory

The priority is a reusable autonomous software delivery service. Bonus Library
is the acceptance project; further product features should serve a named Factory
milestone. AI-generated product descriptions are not Factory worker calls.

## Current evidence, 2026-09-21

- Cloud identities, authoritative DynamoDB state, immutable release storage and
  rollback were verified: `factory/evidence/controller-deployment-2026-09-13.json`,
  `aws-bootstrap-2026-09-13.json` and `aws-rollback-drill-2026-09-13.json`.
- The original Planner → Builder → independent Inspector pilot shipped and
  recovered an artifact. It retired with an explicit budget-history exception;
  replacement cumulative budget controls passed live verification. See
  `factory/evidence/pilot-closeout-2026-09-17.json`.
- Runtime sandbox, bounded repair and liveness components exist. Their presence
  does not prove a continuously operating end-to-end worker.
- `.github/workflows/controller-runtime.yml` is a one-shot bootstrap canary,
  not a reusable scheduler. The retired pilot must not be reactivated by changing
  its status labels. Bonus Library's contract still denies operational role
  activation, even though the product itself is live.

## Completion milestones

| Milestone | Completion evidence | Status |
| --- | --- | --- |
| Durable dispatch | One claim under contention; crash cannot duplicate a provider call; paused/stale work rejected | Ledger implemented and locally tested; live canary pending |
| Cloud worker | Approved task intake → claimed job → independently identified role → persisted result, survives worker restart | Not wired or activated |
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

1. `FACTORY#<factory>#OBJECTIVE#<objective>` / `CAPABILITY#<capability>` with
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
writing them, and bind capability completion to accepted evidence. This PR does
not provide those writers or claim a completed live anti-drift system. It adds a
mandatory consumer gate which fails closed until those prerequisites exist.

Closure blocks future claims; it cannot undo an external operation already
started. The worker must recheck activation before external effects and reconcile
in-flight jobs under the existing pause/termination policy. Budget reservation,
role activation, source review, and Tim's release authorization remain separate.

Progress reports must state the Factory capability, evidence, remaining blocker,
and next action. Count accepted capabilities, not product features or commits.
