# Verified Security static attestation 001

Status: owner approved and completed at 2026-10-03 13:44:32 UTC. Security version 3
made the sole synchronous attestation invocation and one KMS signing call, with
zero retries, model calls or task writes. The function was restored disabled with
reserved concurrency zero. The task remains SECURITY_REVIEW 14, byte-for-byte
unchanged. Other functions, permissions, previous versions and aliases were
verified unchanged. The invocation authorization is consumed; never rerun it.

The deployed source is `73c701546a91326b8ff849dc53d2f9a9d5b2dffc`, package SHA256
`87f58c1f5a2e2b3636b8a50ab1fa1fae1670c7ce2e4f8651c3059aae9226dd28`.
Disabled version 2 and bounded attestation version 3 are retained. Public proof is
`factory/evidence/security-static-attestation-live-proof-2026-10-03.json`, SHA256
`01868bd1a5bffc2f5032e13c9464f536af5dc83780d5c6df6260b7f3a008d34d`.
The signature, report digest and all findings were independently verified after
export. Signed payload digest:
`sha256:e8346508846688c8d925b2cf753c65e1961649c05d26d5a3c28ccc876047b45a`.

This proves the existing Security role signed the exact static report. It does
not resolve the three findings, constitute an independent model assessment,
complete the Security gate, authorize a release or establish autonomous operation.

The completed bounded step is one independently signed static-observation report from
the existing Security Lambda role and enrolled KMS key. The report pins the exact
fingerprint candidate and accepted historical QA gate. It does not execute the
candidate or call a model. This is a reproducible source inspection with explicit
limits, not a penetration test or a completed Security gate.

The report retains three findings: arbitrary caller-supplied paths and symlinks,
potential blocking on special files despite the byte limit, and complete input
disclosure through successful JSON output. These require caller isolation,
host timeouts and output handling. No finding is silently waived or presented
as proof of a filesystem sandbox. A later gate needs a separate reviewed scope,
fresh lease and controller evidence; this attestation cannot advance the task.

## Scope approved and executed

1. Deploy the reviewed immutable package to `tims-factory-review-security`,
   disabled with reserved concurrency zero. Preserve the existing Security role,
   key, all old versions, QA resources, stack parameters and aliases.
2. Publish a bounded immutable configuration and invoke exactly one synchronous
   `security_static_attestation` request, with SDK retries disabled. The nonce,
   source, candidate and five-minute deadline must match deployed configuration;
   the deadline cannot exceed the existing Security enrollment expiration.
3. Verify the signature, report digest, all findings and limitations against an
   independently retrieved public key, then block concurrency and restore the
   disabled environment even on failure. Preserve every invocation journal.

No new IAM permissions, key, model request, lease, task write, scheduler change
or release is included. The original operational execution flag stays false.
Use shared Lambda capacity only during the approved request; no quota increase.

## Review and verification

`security_report.execute` verifies pinned source/QA evidence without executing
candidate code. `security_attestation.handler` is disabled by default. It checks
the role, exact event, active registry and independently retrieved KMS public key
before signing, and rechecks time after report generation. It signs a bounded
digest envelope retaining report provenance and explicit absence of gate authority.
Unexpected signing results have unknown outcomes and must never be retried.

Build with `scripts/build_security_attestation_package.py` outside a clean
checkout. `scripts/prepare_security_attestation_deployment.py` prepares an additive
plan from the actual current stack and immutable S3 object version. Validate the
actual change-set template and summary, including resolved parameter values:
only Security Code/Handler/Timeout/Environment/ReservedConcurrentExecutions may
change, plus one retained immutable version. Do not execute the change set
before owner approval. Record the package digest and change-set identity.

Before invocation, create an exclusive flushed journal outside temporary storage.
A present journal, timeout or uncertain outcome forbids another request; the
nonce is not a durable replay ledger. Verify Security Review v14 remains unchanged
and keep QA/controller, the scheduler and Google broker disabled. Store the signed
report and shutdown checks as evidence, without treating them as gate completion.
