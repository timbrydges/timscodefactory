# Factory acceptance pre-activation review packet

Review the immutable PR head that contains this packet, starting from baseline
`a1fd50f5a48588d65352736f4803bb8658271871`. Tim explicitly waived the
independent pre-activation reviewer for this acceptance task on 2026-09-29.
The exception is recorded in
`factory/evidence/owner-review-exception-2026-09-29.json`; it is an owner
decision, not an independent review, an operational activation, or authority
to spend. Keep the substantive checks below as deployment verification tasks.
Tim is the sole human authority; no second human reviewer is required. The
separate `independent_inspector_service` receipt below belongs to an AI role
that must actually inspect the exact scope before its isolated key signs. It
does not have veto power over Tim's audited owner override or stop order. The
owner exception for PR #198 did not fabricate an inspector receipt or change
the normal automated dispatch rules.

## Exact scope and current state

- Task: `deterministic-text-fingerprint` in private repository
  `timbrydges/tims-factory-autonomy-acceptance`, commit
  `fcb4c535d4ea00962b26db14f59e34917ef2389f`, contract SHA-256
  `7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa`.
- Owner allowance: `gpt-5.6-sol`, USD 5 total, USD 0.25 per call, three calls,
  24 hours, no production release. Source:
  `factory/autonomy/operating-contract.yaml` and its owner evidence.
- Pricing quote: `factory/evidence/openai-gpt-5.6-sol-pricing-quote-2026-09-28.json`,
  expires `2026-09-30T05:45:10Z`. The runtime rejects stale pricing. Renew it
  before activation if the review completes later.
- Receipt roles: owner and inspector live canaries passed in GitHub Actions
  runs `36527044416` and `36527291302`; evidence is
  `factory/evidence/receipt-writer-iam-canary-2026-09-28.json`.
- Broker version `:4`, Builder version `:8`, acceptance schedule `DISABLED`.
  Their deployment, credential metadata and disabled probes are in the
  corresponding `factory/evidence/*live-verification*.json` files.
- Merged PR #198 changed only the approved Sol target's policy and catalog
  switches to `enabled: true`; Terra stays false. The exact profile hashes
  are recorded in `factory/evidence/sol-target-technical-enablement-2026-09-29.json`.
- The disabled schedule's `factory_id` input was corrected from `factory` to
  `tims-software-factory` with the guarded input-only Terraform update. The
  AWS canary passed while the schedule remained `DISABLED`, with zero model
  calls. Evidence: `factory/evidence/disabled-schedule-binding-verification-2026-09-29.json`.
- `guarded_operational_role_activation`, `live_controller_runtime_deployment`,
  and `guarded_schedule_activation` remain pending, so the live authorizer
  still denies. The broker and Builder have separate disabled switches. The
  controller has only a disabled probe, and Terraform keeps the schedule
  disabled. No provider call or approval receipt is authorized by this candidate.

## Review before gate closure or deployment

1. Compare the exact task, source, signed scope, reviewer separation, budget
   reservation, replay and unknown-outcome behavior against the owner terms.
2. Review the independent IAM identities and live canary logs. Confirm each
   can write only its own encrypted versioned receipt and cannot read or
   overwrite another role's receipt.
3. Check the broker-only secret lease, no credentials in Builder, no retry,
   pinned broker version, exact endpoint and response validation. Confirm the
   provider request uses explicit-only caching without breakpoints so its
   USD 0.25 worst-case bound excludes cache-write charges.
4. Inspect this target candidate and the later gate-closing diff. The runtime
   scope must remain the exact Sol target, retain the unapproved challenger
   off, preserve Tim-only release authority, and use a fresh quote. This
   candidate alone does not close any remaining gate.
5. Record the owner exception and exact candidate head in deployment evidence.
   CI success or this packet alone does not close any remaining technical gate.
6. Require a guarded live controller canary that verifies the exact
   task, budget, stop conditions, durable state and replay behavior. Verify
   the pinned broker and Builder deployments with their operational switches
   enabled before closing the role gate. Review the schedule enablement and
   its execution role separately, then canary it under the same limits. The
   present disabled controller probe and schedule do not establish these gates.

The repository includes an `AcceptanceController` guard that reloads the
operating allowance and price before a tick, checks the deployment binding,
and delegates to the bounded scheduler. It is implementation preparation only:
the deployed Lambda remains probe-only. `VersionedS3AcceptanceJobSource` can
restore a deployment-pinned stage plan and two exact receipt versions from a
versioned S3 object, checking its checksum, digest, task, stage and bytes. The
separate receipt transport and intake must still verify the owner and reviewer
signatures. Publishing the reviewed jobs and receipts, deploying the controller
with scoped IAM, and its operational canary are still outstanding.

The controller Lambda now has a guarded composition branch for one pinned
Builder stage: it parses deployment-owned activation and job versions before
constructing DynamoDB state/dispatch/budget adapters, the S3 job and receipt
readers, the public signer registry, and a version-pinned Builder executor.
The controller has no signing key or provider credential, and its guard cannot
execute a provider call. The deployed CloudFormation template still hard-codes
`FACTORY_AUTONOMY_CONTROLLER_ENABLED=false`; no operational IAM, reviewed job
publication or live invocation has been deployed or verified. This branch alone
does not close `live_controller_runtime_deployment`.

`scripts/prepare_acceptance_job.py BINDING.json PLAN.json
RECEIPT_VERSIONS.json INPUT CONTRACT OUT.json` now produces the canonical
`IMPLEMENTATION` job bytes after checking the exact task, activation window,
source and contract digests, input digest, lease, scope payloads and two distinct
version fields. It runs the controller's job decoder and IAM bundle renderer
against those bytes. This is offline preparation: the receipt versions must
come from separately authenticated owner and inspector publication under the
same plan digest, and the emitted job has no S3 version until separately
published and verified. Do not treat the output as a signature, review verdict,
live controller deployment, or permission to enable the schedule.

`scripts/prepare_acceptance_inspector_review.py BINDING.json PLAN.json INPUT
CONTRACT OUT.json` prepares the exact material for the separate AI Inspector.
It validates the same activation and scope bindings, marks task bytes as
untrusted, and emits no verdict, signature, receipt version or model-call
authority. The proposed `ACCEPTED` payload is an input for inspection, not an
Inspector decision. A live Inspector review and separately authenticated
receipt publisher are still required before job publication.

Until the target change and remaining technical gates are recorded,
keep the contract default `DENY`, all operational switches off, and the
schedule `DISABLED`.
