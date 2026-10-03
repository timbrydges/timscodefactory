# Disabled Builder entrypoint staging

Stage reviewed source `535233c6e7e7655ef79e885b9c1a164fd7bee1d4` on the Builder
function only. The exact immutable artifact and AWS change-set preview are recorded
with this review. The prepared update changes Builder code, handler to
`factory_runtime.pilot002_entrypoint.handler`, timeout to 180 seconds, and its
description/source tags. Inspector, QA, all policies and every other resource
must remain byte-for-byte unchanged in the template.

Builder retains `FACTORY_PILOT002_EXECUTION_ENABLED=false` and reserved concurrency
zero. The package has no `PILOT002_ACTIVATION.json`, owner allowance or credentials.
The handler rejects while disabled, and enabling a flag alone would still fail
without valid immutable activation material and the exact owner signature.

`prepare_pilot002_builder_stage.py` rejects deployed baseline drift, a different
source, mutable/wrong S3 artifacts, replacement, extra resource changes, or a
template that opens concurrency. It prepares and validates only; it cannot
execute a change set. The existing deployed Builder code/configuration provides
the rollback baseline. The original 30-second probe deployment predates the live
entrypoint and first-generation policy; this staging puts that reviewed boundary
in place while remaining disabled.

Next requested approval: merge this PR using the owner review override, execute
only the recorded Builder staging change set, and perform read-only deployment
verification. No Lambda invocation, credential read, KMS signing, attempt claim,
model call, enable flag or concurrency increase is included. A future generation
requires a freshly bound activation package and separately approved exact signed
allowance. Do not treat this staging approval as permission for those actions.

Prepared AWS change set: `arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-builder-stage-20261003-001/6aa76c36-1674-44c8-a3b1-b2948e3f7cf2`.

AWS reports `CREATE_COMPLETE` / `AVAILABLE`; it has not been executed.
The immutable artifact is version `LhL.IdMgN_6JbaxPGdnJ3XhkSoHnnRQI`,
ZIP SHA-256 `6dfc5adfd53e0ab9d2d39193313e03807202f0a29654703129bbe0adc3f7ecce`.
The preview records zero credential reads, signatures, provider calls and existing
attempt rows. All three deployed functions were checked disabled with concurrency zero.
