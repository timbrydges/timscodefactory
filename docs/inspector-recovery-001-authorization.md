# Recovery-specific owner authorization

The separately approved table deployment reached CREATE_COMPLETE and its table
is ACTIVE. Read-only verification confirmed encryption, deletion protection,
disabled TTL, an absent recovery attempt, unchanged original Pilot 002 rows,
and all three original workers disabled. No runtime access or model call was
granted by this deployment. The exact evidence is recorded in
`factory/evidence/inspector-recovery-001-ledger-deployed.json`.

The new offline verifier accepts only an
`inspector_recovery001_exact_request_allowance` signed by the enrolled owner key
supplied by trusted deployment material. An old Pilot 002 allowance cannot pass,
even with a valid owner signature. The recovery signature additionally binds:

- The approved recovery scope digest, exact separate table and permanent key.
- Candidate 09c789a902377cb095c20abae89459c4cec3e89e and the fixed reconstructed
  Builder response, with the exact previously counted Inspector request bytes.
- Runtime source, model, packet, original task contract, pricing and readiness.
- One provider call, zero retries, the USD 0.25 hold and cap, and no gate,
  release or task-state authority.
- Required failed-review response capture, limited to 262,144 provider bytes.

The verifier checks current price/readiness/allowance windows and returns only
the separate recovery store's claim arguments after signature verification.
Those claim arguments carry the maximum quote as well as the full permanent
hold. Tests use an ephemeral local test key and historical public context;
neither is live authorization. Tests cover wrong signatures, old allowances,
changed candidates/requests, stale observations, expanded caps and roles, wrong
table/key, disabled capture, and verified claim isolation.

This is an unwired verification library. It performs no signing, provider calls,
AWS writes or default credential discovery. The source commit and observations
are deployment-supplied claims; a future handler must verify its actual runtime
identity and immutable deployment configuration. Price validity, source identity,
credential access, and the truth of readiness evidence still require independent
deployment checks. A valid budget proposal is not an executable allowance.

## Approval boundary

Approve the source merge with the required owner review override after CI.
No new KMS or IAM grant, workflow dispatch, runtime deployment or model call is
included. The remaining work is isolated signer/runtime integration, exact AWS
preview, current price/readiness observations, and a separately approved live
allowance with a one-shot runner and verified shutdown. The original Inspector
attempt remains permanently locked and the candidate remains an unapproved draft.
