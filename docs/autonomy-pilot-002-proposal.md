# Proposed next task and budget: safe workspace fingerprint pilot

Status: owner approved the task and budget on 2026-10-03, recorded in
`factory/evidence/pilot-002-task-budget-approval.json`. This is not a live authorization,
provider reservation, IAM grant, scheduler activation or change to the completed
acceptance contract. Historical model budgets and one-call approvals are not
reused. The existing contract stops at RELEASE_READY and prohibits production.

## Approved task and budget

The approved non-production task is `safe-workspace-fingerprint-001`, with a new
maximum provider budget of USD 0.75 total, at most USD 0.25 reserved per attempt,
and at most three attempted provider calls: one OpenAI Builder, one Anthropic
Inspector and one Google QA assessment. These are spending ceilings, not price
quotes or a claim that provider readiness is already established. No automatic
retry, fallback call, remediation cycle or over-cap reservation is permitted.

The work would harden the fingerprint CLI's input boundary, addressing the two
remaining code-level findings instead of relying solely on caller discipline.
It starts from the existing private acceptance repository
`timbrydges/tims-factory-autonomy-acceptance`, baseline main commit
`1c876ac42305fb9295424759424a74263e4fc330`, which already contains Builder 006.
Create a separate task and branch; preserve all old task, lease and budget history.

## Proposed acceptance behavior

- Python 3.12 on Linux; only standard-library implementation dependencies.
- Accept a relative input path within an explicitly supplied private fixture
  workspace. Reject absolute paths, parent traversal and symlink components.
- Open without blocking on special files, check the opened descriptor is a
  regular file, and read at most 4097 bytes. Reject non-regular, oversized,
  unreadable and invalid UTF-8 inputs without partial stdout.
- Preserve the existing canonical byte_count/sha256/text JSON for valid input.
  Full input echo remains intentional; use only generated public synthetic data.
  Do not claim a general OS sandbox or safety for sensitive real-world inputs.
- Test normal ASCII/Unicode, byte limits, traversal, symlinks and special files
  in disposable private fixtures. Bound every child process with a timeout.
- Builder changes only `fingerprint.py` and `tests/test_fingerprint.py`.
  Infrastructure and contract changes remain operator-reviewed work, outside the
  generated candidate. Produce a reviewable PR; no automatic merge or release.

## Conditions before any live activation

Prepare a distinct reviewed task contract and exact deployment/access plan.
Verify all three provider routes, credential boundaries and budget ledgers;
obtain fresh model/pricing evidence for each exact configured model and reserve
conservatively within both caps before sending any request. If one provider is
unavailable or a reservation cannot fit, keep the pilot disabled and report it.
Do not silently substitute an unsigned transcript or another provider.

Present concrete security-sensitive permission grants and live activation for
approval when ready. Task/budget approval alone does not grant those permissions.
Use least privilege for the exact new task and branch. No production access,
secrets in model inputs, personal data, broad repository access or standing
autonomous authority is included.

The proposed active run lasts at most one hour and stops on any uncertain
provider outcome, failed independent verdict, cap reached, missing evidence,
source drift or completion. Then disable execution and remove temporary access.
Approval of this proposal does not extend any existing signer enrollment.

The exact task contract is `factory/autonomy/pilot-002-contract.json`.
The next bounded initialization proposal is `docs/pilot-002-bootstrap.md`.
