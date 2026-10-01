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
