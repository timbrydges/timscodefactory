# Factory acceptance pre-activation review packet

Review the immutable PR head that contains this packet, starting from baseline
`a1fd50f5a48588d65352736f4803bb8658271871`. This is preparation for an
independent decision, not an approval or activation. The reviewer must be a
different authenticated identity from Tim, the Builder, and the author of the
activation change. Record the reviewed commit, PR review URL, findings, and
decision in durable evidence before `independent_pre_activation_review` can
move to verified.

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
- This draft candidate changes only the approved Sol target's policy and
  catalog switches to `enabled: true`; Terra stays false.
  `approved_target_technical_enablement`, `independent_pre_activation_review`,
  `guarded_operational_role_activation`, `live_controller_runtime_deployment`,
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
5. Require a signed or authenticated review tied to the exact activation PR
   head, with concrete findings and an explicit approve or changes-needed
   decision. A self-review, CI success, synthetic signature, or this packet
   alone does not close the independent review gate.
6. Require an independently verified live controller that enforces the exact
   task, budget, stop conditions, durable state and replay behavior. Verify
   the pinned broker and Builder deployments with their operational switches
   enabled before closing the role gate. Review the schedule enablement and
   its execution role separately, then canary it under the same limits. The
   present disabled controller probe and schedule do not establish these gates.

The repository includes an `AcceptanceController` guard that reloads the
operating allowance and price before a tick, checks the deployment binding,
and delegates to the bounded scheduler. It is implementation preparation only:
the deployed Lambda remains probe-only, and the durable job source, receipt
inputs, role transport, IAM and operational canary are still outstanding.

Until that decision and the separately reviewed target change are recorded,
keep the contract default `DENY`, all operational switches off, and the
schedule `DISABLED`.
