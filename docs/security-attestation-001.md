# Proposed Security static attestation 001

Status: prepared for approval. No Security invocation, deployment, model request,
task transition or release is authorized by these files.

The next bounded step is one independently signed static-observation report from
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

## Requested approval

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
