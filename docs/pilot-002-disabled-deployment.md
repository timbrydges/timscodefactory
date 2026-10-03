# Pilot 002 disabled runtime deployment preview

`prepare_pilot002_runtime.py` renders a create-only CloudFormation template and
validates the returned change set against exactly nine additions in account
666730517561, ca-central-1, stack `tims-factory-pilot-002-runtime-disabled`:

- Functions `tims-factory-pilot-002-builder`, `tims-factory-pilot-002-inspector`,
  and `tims-factory-pilot-002-qa`.
- Three corresponding new roles, each function name suffixed `-disabled`.
- Three `/aws/lambda/<function-name>` log groups with seven-day retention.

Each role trusts Lambda and can only create streams and write events in its own
log group. There are no managed policies, model permissions, secret access,
database access, schedules, event mappings, function URLs or cross-role grants.
The functions use Python 3.12 x86_64, 256 MiB, a 30-second timeout, the probe-only
handler, explicit execution-disabled flags and reserved concurrency zero.
Existing Factory resources are not referenced or modified.

Code must name an immutable S3 object version and exact source commit. The
separately recorded ZIP digest must match the object and deployed CodeSha256.
Preview validation rejects resource removal, duplication, modification, extra
resources, pagination, wrong account/stack and template substitutions.

## Approval and execution boundary

Rendering, building, uploading the public package to existing artifact storage,
and creating an unexecuted change set prepare the review. They do not authorize
execution. The owner must approve the exact source PR override and reviewed AWS
change set before roles/functions/log groups are created. Any changed artifact or
resource scope requires another review.

After an approved creation, the proposed verification is one synchronous probe
per function: confirm code hash, role and disabled flags, temporarily remove that
function's concurrency-zero reservation to use the account's shared pool, invoke
only the exact package probe, then restore concurrency zero in a finally block.
No reserved capacity increase is requested. The probe cannot dispatch a model,
even if an execution flag is changed. A failed or uncertain probe is investigated
without repeated invocation. Postchecks must verify all three concurrency-zero
settings, logging-only roles, no changes to old provider flags or attempt rows,
and record actual results rather than claiming deployment from template creation.

No such creation or probe execution is performed by the preparation script.
This foundation permits package verification only; live generation still needs a
separately reviewed runtime boundary, provider access, credentials, fresh evidence,
signer enrollment and exact owner allowances. AWS artifact storage, probe compute
and log usage are separate from the model-call budget.
