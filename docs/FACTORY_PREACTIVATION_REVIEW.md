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
- The policy and catalog still set `coding_primary_sol_live.enabled: false`.
  `approved_target_technical_enablement` and
  `independent_pre_activation_review` remain pending. The broker, Builder,
  controller and schedule have separate disabled switches. No provider call
  or approval receipt has been authorized by these preparations.

## Review before any enablement

1. Compare the exact task, source, signed scope, reviewer separation, budget
   reservation, replay and unknown-outcome behavior against the owner terms.
2. Review the independent IAM identities and live canary logs. Confirm each
   can write only its own encrypted versioned receipt and cannot read or
   overwrite another role's receipt.
3. Check the broker-only secret lease, no credentials in Builder, no retry,
   pinned broker version, exact endpoint and response validation. Confirm the
   provider request uses explicit-only caching without breakpoints so its
   USD 0.25 worst-case bound excludes cache-write charges.
4. Inspect the proposed **activation** diff itself. It must change only the
   intended target and gate evidence, retain the unapproved challenger off,
   preserve Tim-only release authority, and include a fresh quote. Do not
   treat this preparation PR as the activation diff.
5. Require a signed or authenticated review tied to the exact activation PR
   head, with concrete findings and an explicit approve or changes-needed
   decision. A self-review, CI success, synthetic signature, or this packet
   alone does not close the independent review gate.

Until that decision and the separately reviewed target change are recorded,
keep the contract default `DENY`, all operational switches off, and the
schedule `DISABLED`.
