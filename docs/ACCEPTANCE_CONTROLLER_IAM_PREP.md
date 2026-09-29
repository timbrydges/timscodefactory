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
