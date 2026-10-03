# Security reviewer enrollment proposal 001

Status: prepared, not authorized or applied. QA gate 001 has advanced the task to
SECURITY_REVIEW 14. The existing Security function remains the identity-probe
handler with operational execution disabled; no Security review was invoked.

The next proposed change adds only the existing public key for
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
signature was verified locally. The prospective appended registry passes the
registry validator, while the actual registry remains byte-for-byte unchanged.
The observation is in `factory/evidence/security-key-observation-2026-10-03.json`.
Security uses shared concurrency, not a reserved zero cap; its operational flag
and probe-only handler are the current execution boundary. No concurrency change
was made during observation.

Owner approval is required because enrollment makes this key trusted for the
Security identity. It does not by itself authorize a verdict: a reviewed isolated
executor, exact scope, fresh lease and controller verification remain necessary.
This proposal includes zero new keys, IAM changes, model calls, signing calls,
task writes, scheduler activation or production release.

After approval, re-read the same AWS key and role, check the registry digest and
QA proof, regenerate the one-entry preview with this proposal's merged review
commit and a fresh window no longer than 86400 seconds, then validate and review
the exact registry diff. Do not extend QA enrollment or reset any gate history.
An expired observation requires a new read, not a new key or a provider call.
