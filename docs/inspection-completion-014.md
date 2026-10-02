# Inspector 014 completion and next pilot draft

The owner authorized model-free integration of the accepted Inspector 014
verdict. The exact signed result and INSPECTION v10 baseline are pinned in
`factory/evidence/inspector-014-completion-authorization.json`.

The controller verifies the enrolled Inspector signature, candidate, contract,
test evidence and original expiry. It issues a reconciliation lease (v11), then
uses the normal INSPECTION to QA transition (v12). This lease imports an existing
review; the original signature does not cover the new lease or authorize a new
dispatch. Both changes use the existing atomic state/audit persistence. No
owner override, reset, lease deletion, budget mutation or model call occurs.

A duplicate request is a no-op. An uncertain state write is reconciled against
the exact baseline, import-lease state or completed state. Any other state or
expired evidence fails closed. Provider attempt 014 remains consumed forever.

Deploy the new controller code with its standard disabled template first.
`prepare_inspection_completion.py` prepares a separate configuration change set
for `enable` or `restore`; execution journals its attempt before the AWS call.
Temporary IAM permits only GetItem/PutItem/UpdateItem on this task partition,
expires at 2026-10-03 03:01:53 UTC, and grants no model, secret, signing or Lambda
invocation permissions. Autonomy and scheduling remain disabled. After the
single model-free controller operation, restore the original logging-only
template and verify its alias, published version, flags and IAM.

The mock workflow test exercises real intake, local fixture signatures, worker,
and result progression through all seven non-release stages. Providers and
persistence are in memory. It verifies duplicate delivery, unknown provider
outcomes and invalid signatures; it is not proof of live provider quality,
DynamoDB contention, or unattended production readiness.

## Verified live completion

On 2026-10-02 at 19:36:58 UTC, controller version 30 consumed the signed verdict
once and advanced the task to QA v12. The final audit at 19:39:22 UTC verified
all 26 budget rows unchanged, all 15 prior non-state task records unchanged,
exactly two new normal controller audit events, and all seven leases preserved
and revoked. Controller version 31 restored the logging-only role and passed
the disabled runtime probe. Every operational execution flag and the schedule
remain disabled. No model call or production release occurred.

The deployed runtime is PR #289, commit
`c8da72cd4cd044fdf37e2c174edff510b0d3063a`. Its Linux CI ran 779 tests with 13
existing skips; the static, simulation, Docker, HTTP and TLS gates passed.
The checked-in proof is
`factory/evidence/inspector-014-completion-proof-2026-10-02.json`.
This evidence-only update requires no redeployment.

## Future pilot: draft only, not an activation

Proposed scope: one exact candidate, beginning at QA, followed by independent
security review, stopping at RELEASE_READY. No production release, additional
Builder work, state reset or recurring schedule is included.

Before activation, prepare exact QA and security jobs, isolated role executors,
independent signed scope receipts, pinned code/artifact versions and fresh
pricing. Validate failure and duplicate behavior for those deployed transports.
The current commissioning configuration authorizes only the already consumed
Builder attempt; it is not authorization for these later roles.

Request fresh approval only after those artifacts are reviewable: exact call
count, conservative per-call reservations, total cap and expiry. Do not reuse
the residual USD 0.13840 beneath the previous USD 5.25 ceiling as an allowance.
Retain all prior reservations, including unknown outcomes. Keep automatic
provider retries at zero and stop on any unknown outcome, failed signature,
expired approval or budget denial. A recurring schedule needs its own explicit
bounded approval and verified emergency stop.
