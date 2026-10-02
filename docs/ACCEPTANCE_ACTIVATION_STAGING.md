# Acceptance activation preparation

`scripts/prepare_acceptance_activation_bundle.py BINDING.json JOB.json OUT.json`
prepares matching broker, Builder and controller environment updates and an
exact controller IAM policy. It performs no AWS IO, publishes no object,
signs no receipt, changes no contract gate and authorizes no model call.
All three execution flags in the output remain `false`.

The binding has exactly these fields:

- `activation_id`, `source_commit`, `contract_digest`, `starts_at`, `expires_at`
- `builder_version_arn`, `broker_version_arn` (numeric immutable versions)
- `job_version_id` (published immutable version, not `NOT_PUBLISHED`)
- `provider_secret_arn` (the exact acceptance secret ARN, never its value)

Supply the exact bytes of the published job. The existing controller decoder
checks its digest, source and receipt pins. The publication validator also
checks current owner/reviewer receipt expiry, accepted scope, lease expiry and
exact task input and contract. The activation must end before the pricing
quote expires. Pending operating-contract gates appear as blockers; preparation
does not clear them or make an inactive contract active.

The output is a preparation artifact, not a deployable authorization. Its
`environment_updates` must be merged with the existing role environment,
preserving signing and other reviewed settings. No deployment command is
provided by this tool. A subsequent guarded deployment must verify the actual
S3 versions and signatures, durable task state, unused activation budget,
artifact/source bindings, IAM and disabled schedule. Local version names alone
are not evidence that those objects exist. The output file is created only if
all preparation checks pass and is never overwritten.

Freeze the operational candidate before requesting an independently authorized
Inspector review. A review of an older commit or expired scope cannot authorize
a new candidate. Consumed Inspector activations must never be reset or retried.

## Guarded disabled configuration deployment

`scripts/stage_disabled_acceptance_config.py prepare COMPONENT BINDING JOB PLAN`
rebuilds the bundle and prepares one CloudFormation change set for `broker`,
`builder` or `controller`. `execute PLAN` permits exactly one in-place function
environment change, with all existing code, IAM, parameters, published versions
and the controller alias preserved. It checks the disabled no-retry schedule,
source checkout, template, runtime settings and revision again before execution.
The prepared template is compared with the actual AWS change set before use.

The staging command never signs receipts, grants permissions, publishes a
Lambda version, changes an alias, enables a schedule or invokes a function.
It updates only the unpublished function configuration. Receipt authenticity,
deployed source matching and all final activation gates remain required before
any live activation; a staged configuration is not evidence those gates passed.

An uncertain execution is saved as attempted before the AWS request. Use
`reconcile PLAN` to read the result; never retry `execute`. Reconciliation and
`verify PLAN` remain read-only even after receipt expiry. Plans cannot be
overwritten during preparation. Subsequent code-deployment tools deliberately
reject the staged template until that configuration is explicitly accounted for.

The model-free staging canary requires no job or receipt:

```text
python scripts/stage_disabled_acceptance_config.py prepare-canary controller CANARY_PLAN
python scripts/stage_disabled_acceptance_config.py execute CANARY_PLAN
python scripts/stage_disabled_acceptance_config.py prepare-cleanup CANARY_PLAN CLEANUP_PLAN
python scripts/stage_disabled_acceptance_config.py execute CLEANUP_PLAN
```

It adds only an inert `FACTORY_CONFIGURATION_CANARY` marker, verifies the
environment-only update, then removes exactly that marker with the same guard.
Published runtime versions and the acceptance alias must remain unchanged
through both steps. A canary is deployment-mechanism evidence, not a substitute
for paid scope review, signed receipts or final activation verification.

## Owner receipt publication

The `factory-owner-signing` workflow has a separate `publish_owner_receipt` job.
It remains disabled unless `FACTORY_OWNER_RECEIPT_PUBLICATION_ENABLED` is exactly
`true`. It requires the owner actor on `main`, the first workflow attempt, the
exact plan encoded as base64 and a separate owner-approved `sha256:` plan digest.
Inputs reach Python through environment variables, not shell interpolation.

`publish_acceptance_owner_receipt.py` rejects a changed source, task, scope,
lease, digest, price window or signer identity before signing. It uses the
enrolled non-exportable owner KMS key and writes only the owner's encrypted,
checksum-bound, immutable receipt with `IfNoneMatch: *`. It cannot generate an
Inspector approval or enable execution. No model call is made. Both workflow
reruns and client retries are disabled; an uncertain result must be reconciled
by reading the exact receipt key and verifying its signature before proceeding.
An attempt record is retained as a workflow artifact even when publication fails.

Do not enable or dispatch this job with a stale or placeholder plan. Prepare the
final candidate and exact scope first. A signed owner receipt is only one input
to the later guarded activation, and does not clear the operating-contract gates.

## Signed execution-job publication

`publish_acceptance_job.py verify BINDING PLAN RECEIPT_VERSIONS OUT` verifies
the current clean source, fixed acceptance input/contract, fresh receipt and
pricing windows, authoritative unleased task version, and unused activation
budget. It reads only the two pinned S3 receipt versions and verifies their
owner and independent Inspector signatures against the trusted key registry.
The supplied version names or an `ACCEPTED` field alone cannot pass this gate.
Verification performs no cloud writes.

`publish_acceptance_job.py publish BINDING PLAN RECEIPT_VERSIONS ATTEMPT` repeats
those checks and uploads exactly one encrypted, checksum-bound job to
`factory-autonomy-jobs/<activation_id>/IMPLEMENTATION.json`. It uses an exclusive
local attempt record, a conditional `IfNoneMatch: *` S3 write, and no client
retries. The returned immutable version and stored bytes are checked before
reporting publication. The job digest and version can then be supplied to the
activation-bundle preparer with the identical bytes from the offline job encoder.

If the upload response is lost, `publish_acceptance_job.py reconcile ATTEMPT`
only reads the object and matches its complete bytes, checksum and immutable
version to the attempted job. It never uploads again. Reconciliation proves
publication, not current authorization; final activation must recheck receipt
expiry, state, budget, source, IAM and runtime settings. None of these commands
reserve provider spend, change task state, sign receipts, invoke a role, grant
IAM, enable execution or clear any operating-contract gate.
