# Proposed synthetic-only Security gate 001

Status: owner authorized the bounded operation, but the first lease request
was rejected before any state write or Security signature. The generated audit
identifier was 41 characters; DynamoDB's adapter permits at most 36. The fix
uses a four-character prefix plus the same 32 hexadecimal hash characters.
Regression coverage now exercises both lease and completion through the real
storage adapter, including its transaction-token validation.

Containment was verified at 2026-10-03 14:27 UTC: task SECURITY_REVIEW version 14
unchanged, zero signing invocations, both functions disabled, and temporary
access removed. The failure proof is
`factory/evidence/security-gate-001-contained-failure-2026-10-03.json`.
Any continuation must preserve the original single-signature limit, durable
journals and maximum one-hour access window; no invocation may be blindly
repeated. The original scope acceptance remains synthetic-only.

The proposed gate verifies the pinned successful Security validation and its
historical public-key enrollment, the exact candidate/contract, the accepted
scope and all retained findings. It never executes the candidate or a model.
It signs a fresh gate verdict carrying the synthetic-only scope, open findings,
absence of an OS sandbox claim, and production_release_authorized=false.

## Next approval requested

Authorize the exact reviewed package on the existing Security and controller
functions, initially disabled, and one bounded Security gate operation:

1. Temporarily grant the controller GetItem, PutItem and UpdateItem on only
   `FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint` in
   `tims-software-factory-state`. Use both LeadingKeys and an absolute time
   condition, for at most one hour and within the existing Security enrollment.
   No delete, scan, provider, secret, KMS or invocation access is granted.
2. Issue one fresh Security lease: SECURITY_REVIEW version 14 to version 15.
   Have the existing independently enrolled Security role sign exactly once,
   without retry. Preserve a flushed, exclusive invocation journal.
3. Verify that exact signature and scope in the controller and consume the
   evidence once: SECURITY_REVIEW version 15 to RELEASE_READY version 16.
   Revoke the lease and preserve prior lease/evidence history and audit events.
4. Disable both functions, restore zero concurrency, remove the temporary policy,
   and verify the controller is back to logging-only access. Preserve old
   versions, aliases, keys, all other functions and stack parameters.

RELEASE_READY here records completion of this synthetic benchmark's review
sequence. It does not permit RELEASING, deployment of the candidate, real user
inputs, scheduled operation or unrestricted Factory autonomy. The original
contract continues to prohibit production release. The scheduler, QA and Google
broker remain disabled. No enrollment extension or new model budget is included.

The two execution handlers reject missing/expanded/expired deployment approval,
wrong roles, competing execution flags and incorrect event fields. The
controller rejects state drift, erased history, missing leases, pre-lease
signatures and re-used evidence. Committed state writes can be reconciled by
reading exact state; an uncertain signing invocation must never be retried.

The permission helper prepares both the exact grant and restoration templates.
Validate actual change-set contents and resolved parameters before execution.
If the enrollment cannot cover the entire operation, retain the hold; approval
does not extend its expiration (2026-10-04 13:27:36 UTC).
