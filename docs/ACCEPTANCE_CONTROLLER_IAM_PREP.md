# Acceptance controller IAM preparation

`scripts/prepare_acceptance_controller_iam.py` renders a policy for review. It
does not call AWS, attach a policy, change a Lambda, or activate the schedule.
The currently deployed disabled controller role remains logs only.

The binding JSON must contain exactly `activation_id`, `builder_version_arn`,
`job_version_id`, `receipt_plan_digest`, `owner_receipt_version_id`, and
`reviewer_receipt_version_id`. Obtain these from the reviewed immutable job and
authenticated receipt publication. Never use `null`, `$LATEST`, an alias, or a
placeholder as a deployment pin. Generate the review artifact with:

```sh
python3 scripts/prepare_acceptance_controller_iam.py binding.json controller-policy.json
```

For deployment preparation, use the combined renderer instead. Its binding
contains exactly `activation_id`, `source_commit`, `contract_digest`,
`starts_at`, `expires_at`, `builder_version_arn`, and `job_version_id`. Supply
the exact reviewed `IMPLEMENTATION.json` bytes:

```sh
python3 scripts/prepare_acceptance_controller_bundle.py binding.json IMPLEMENTATION.json controller-bundle.json
```

The combined renderer runs the runtime job decoder against those local bytes,
then derives the receipt pins, object digest, controller configuration and IAM
policy together. It cannot establish that the local bytes or supplied version
match S3. Before deployment, a separate AWS verification must compare the
versioned object's checksum and content with the resulting digest, verify both
receipt object versions and signatures, compare the job state version with
durable state, and confirm the source commit, allowance and current quote.

Review the generated document and exact deployment binding together. The
policy limits DynamoDB task/scope keys and one activation budget key, reads only
three named S3 object versions, and invokes only a numeric Builder version.
The two receipt objects are read by the controller but signed and published by
separate roles. The policy grants no secret access, receipt publication, IAM
mutation, or production release. The scope objective prefix remains a wildcard
because the objective is carried in signed scope and job content, while the
factory and acceptance task namespace are fixed.

This is preparation only. Attaching this policy, setting the controller's
operational switch, and enabling the EventBridge schedule require the later
review and guarded deployment gates. Each should verify deployed IAM and the
exact pinned binding before any live acceptance dispatch.
