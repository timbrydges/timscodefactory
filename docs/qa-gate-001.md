# Proposed QA gate 001

Status: gate operation approved and code deployed; blocked before lease issuance.
QA remains version 12. No gate signing invocation or state write occurred.

## Verified permission blocker, 2026-10-03

The controller invocation failed at its first DynamoDB GetItem because its role
was logging-only. Inspector completion had temporarily granted state access and
then removed it. The original proposal incorrectly assumed existing state access.
That assumption is corrected here; the previous approval expressly excluded IAM
expansion, so it does not authorize restoring these permissions.

Both gate flags were restored to false and QA/controller reserved concurrency
to zero. Existing versions, acceptance alias, IAM and Security resources were
preserved. The single QA signing authorization remains unused; never rerun the
original operator script or erase its activation/lease-failure journals.

`prepare_qa_gate_access.py` prepares a separate, unapplied permission proposal:
only GetItem, PutItem and UpdateItem on the exact fingerprint-task partition of
the existing state table. IAM conditions require the exact leading key and limit
access to at most one hour, ending before the existing QA enrollment expires.
There is no delete, scan, secret, provider, KMS or Lambda invocation permission.
The existing logging policy and all function/version/alias resources remain intact.

After separate owner approval, compare actual inline/attached policies against
the saved logging-only observation, prepare the exact live-template change set,
and validate its actual template and resource changes with the helper. Do not
change IAM before approval. Preserve the full original template for restoration.
Use one common fresh window for IAM and gate configuration; a stale preview is
not an extension of an old permission or lease. Verify effective permissions with
read-only IAM simulation before invoking the controller. Since the first failed
call performed only a denied read, require exact QA 12 and an absent signing
journal before resuming the approved operation. Journal any controller continuation
separately; never repeat or replace a signing request once its journal exists.

After success or failure, block the functions, restore disabled environments and
remove the temporary policy, verifying the role is logging-only again. The IAM
deadline independently denies state access if cleanup is interrupted. Do not
extend key enrollment, reset task history or start Security execution.

## Original approved gate scope (permission prerequisite was missing)

The proposal binds the reviewed fingerprint candidate, the immutable QA executor
attestation from version 4, the recorded Google assessment and an exact live QA
state snapshot. Historical signature verification establishes test provenance,
not current permission. The Google response is a pinned operator-recorded unsigned
response, not a provider-signed message. Owner acceptance of using that specific
record is required; the new QA signature must not claim Google authenticated it.

## Proposed approval scope

Authorize the existing controller and QA roles to perform only:

1. Issue fresh lease `qa-gate-001`, preserving all history: QA 12 to QA 13.
2. Make one QA gate signing invocation, without retry, binding the accepted
   evidence, candidate, contract, source, approval nonce, lease and deadline.
3. Verify that signature and the actual live lease in the controller; advance
   QA 13 to Security Review 14 through the normal audited state machine.
4. Disable the gate entrypoints and block further QA signing afterward.

The activation window and lease are at most one hour and cannot outlast the
existing QA enrollment. The original approval included no model requests, Google replay, new key, IAM expansion,
Security execution, scheduler activation or release. Any missing or
changed evidence, rejected assessment, invalid signature, expired permission or
unexpected task state stops progression. A stopped run does not reset history.

## Reviewed implementation

`qa_gate.evidence` verifies the historical QA signature at issuance, report digest
and 18 cases, the exact candidate packet, and pinned Google record/proof bindings.
`QaGateController.issue_lease` accepts only the exact captured baseline or its own
already committed lease. `complete` requires a new signature created after the
lease, the approved evidence, current enrolled key and exact leased state. Both
writes use normal conditional DynamoDB transitions and audit records. Unknown
commit outcomes require read-only reconciliation before any continuation; repeated
reads of a committed stage do not create another lease or consume evidence twice.

The QA publisher has only its existing KMS role permissions and does not read or
write the state table. It signs the deployment-configured lease binding; the
controller independently confirms the actual lease before advancing. This is a
bounded publication of previously collected review evidence, not a new model
review or a new execution attestation.

## Deployment and single-attempt procedure after approval

Run `prepare_qa_gate.py` from the clean merged source to save the offline proposal.
Build both roles using `build_qa_gate_package.py`. Download and verify actual
deployed bytes and public registry before enabling anything. Keep existing
immutable versions and the acceptance alias intact. Preserve all IAM/KMS/Security
resources. Use the controller handler `factory_runtime.qa_gate_runtime.controller_handler`
and QA handler `factory_runtime.qa_gate_runtime.signer_handler` on dedicated
immutable versions. Both default to rejection without explicit enablement.

Trusted deployment environment `FACTORY_QA_GATE_CONFIG` must contain exactly:
`authorization_id=qa-gate-001`, `owner_identity=tim_brydges`, `approved=true`,
the actual package `source_commit`, integer Unix `not_before` and `expires_at`,
a fresh 32-character hexadecimal `nonce`, and
`recorded_google_evidence_accepted=true`. Populate approval only after the owner
accepts this scope. Both roles use the same configuration. Set
`FACTORY_QA_GATE_ENABLED=true` only within that approved window; keep the general
controller and operational execution flags false. Retain the QA role/key binding.

Events contain `kind`, `source_commit`, `authorization_id` and `nonce`. Controller
kinds are `issue_qa_gate_lease` and `complete_qa_gate`; only completion also carries
`result` (the exact signed publisher response). QA kind is `publish_qa_gate`.

Read the live task first and compare it to the captured baseline. After lease
issuance, verify QA 13 and the exact lease; wait until the first whole UTC second
strictly after its issuance before invoking the signer. Create an exclusive,
flushed operator journal before the single synchronous signing invocation. Disable
SDK retries. A present invocation journal, timeout or uncertain signature forbids
another signing request. The nonce is not a durable signing ledger.

This account has ten shared Lambda execution slots and cannot reserve one slot.
If required, temporarily use existing shared capacity for the approved request;
do not increase quotas. Block QA concurrency immediately afterward, including on
failure. Independently verify the signed payload before passing it to the
controller. Verify final task version, consumed evidence and preserved/revoked
leases. Keep schedule and Google broker disabled. Record actual outcomes and
restore disabled configurations even when an intermediate stage fails.
