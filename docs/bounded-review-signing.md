# Fresh bounded review signatures

`ReviewAllowanceSigner` uses the existing isolated owner role and enrolled key
to sign only the exact `bounded_review001_provider_allowance` validated against
deployment-owned scope, pricing and readiness. The owner workflow must first
authenticate and qualify those inputs; matching digests do not establish their
provenance. Per-role USD0.25, run USD0.75 and aggregate USD2.75 ceilings remain.

`ReviewRoleResultSigner` supports Builder, Inspector and QA using their distinct
existing roles and keys. It binds factory/task, full dispatch request, dispatch
ID and producer identity, and permits only a bounded output digest with a
maximum five-minute receipt lifetime. `RoleExecutionService` must enforce live
scope, persisted claims and provider execution before calling this signer.
A result signature establishes origin, not acceptance or release authority.

Both adapters perform no I/O at construction and default to disabled. They
check fresh enrollment, current clock, unique identity keys, isolated STS
session and exact KMS public key before signing. Enrollment is checked again
after public-key reads and after signing. Signature responses are verified
locally. Once remote work starts, each instance consumes its attempt, including
unknown outcomes; concurrent calls cannot create a second signature. The SDK
client supplied by deployment must also disable retries. Permanent provider
send claims remain a separate requirement and are never reset here.

Historical signers, workflows and enrollments are unchanged. These classes
have no public endpoint, deployment, scheduler, provider access or live grants.
Independent Product Spec scope-review signing and runtime composition remain
separate integration work. Tests use real Ed25519 with a simulated KMS boundary;
they do not issue live review authority.
