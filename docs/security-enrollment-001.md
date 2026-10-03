# Security reviewer enrollment proposal 001

Status: owner approved; the verified key is enrolled in the repository registry
from 2026-10-03 13:27:36 UTC through 2026-10-04 13:27:36 UTC (exclusive).
The review commit is `91db9f28231c02fdd6dd303f3b554c6974d74a05`. Existing registry
entries are unchanged. Fresh AWS observation and enrollment evidence are saved in
`factory/evidence/security-enrollment-observation-001.json` and
`factory/evidence/security-enrollment-001.json`. No runtime deployment, Security
execution, signing, model request or task write was performed for enrollment.

The original QA executor registry is now an immutable hash-pinned historical
snapshot. Historical QA verification uses that snapshot, while new approvals and
gate signatures continue using the current registry and its active-key checks.
Adding Security trust therefore preserves past provenance without extending
expired permissions. Existing deployed immutable versions remain unchanged.

## Approved proposal and remaining execution boundary

QA gate 001 has advanced the task to
SECURITY_REVIEW 14. The existing Security function remains the identity-probe
handler with operational execution disabled; no Security review was invoked.

The approved change adds only the existing public key for
`deep_security_reviewer_service` to `factory/profiles/scope-signers.json` for a
maximum of 24 hours after application. Every existing entry remains unchanged.
The preview entry and exact registry/QA proof bindings are in
`factory/evidence/security-enrollment-proposal-001.json`.

- Existing key: `arn:aws:kms:ca-central-1:666730517561:key/12303b9c-fa89-44a2-8864-fbc7b3903ca9`.
- Existing role: `arn:aws:iam::666730517561:role/tims-factory-review-security`.
- Public fingerprint: `sha256:4629480d8cb236c32586bfda8dd5985c44954ee02836e37fc12e44b5beea32fe`.
- Candidate: `09a758184c890eda200326a18fb166641194e32e`.
- Security packet: `sha256:401d2cccb7066e68256cbd951bb5e32b2ce4b5429cf8cf224f47d90bd09c3185`.

The fresh AWS observation confirms the enabled Ed25519 SIGN_VERIFY key, supported
algorithm, public DER bytes, Lambda role binding and Lambda-only role trust.
The public key matches the pinned bootstrap proof; its historical challenge
signature was verified locally. At proposal time the prospective registry passed
validation while the actual registry remained unchanged. The initial observation
is in `factory/evidence/security-key-observation-2026-10-03.json`; the fresh
application observation is recorded separately above.
Security uses shared concurrency, not a reserved zero cap; its operational flag
and probe-only handler are the current execution boundary. No concurrency change
was made during observation.

Owner approval was required because enrollment makes this key trusted for the
Security identity. It does not by itself authorize a verdict: a reviewed isolated
executor, exact scope, fresh lease and controller verification remain necessary.
This proposal includes zero new keys, IAM changes, model calls, signing calls,
task writes, scheduler activation or production release.

Application re-read the same AWS key and role, checked the registry digest and
QA proof, and regenerated the one-entry preview with the merged review commit
and a fresh 86400-second window. The exact registry diff and activation/expiry
boundaries are validated. Do not extend enrollment or reset any gate history.
An expired observation requires a new read, not a new key or a provider call.
