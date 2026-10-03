# Builder activation capacity blocker

PR #349 was merged and the isolated owner workflow signed its exact allowance
once (run `37160620999`). AWS rejected the subsequent Builder update before
any Lambda invocation because a reservation of one would reduce unreserved
concurrency below the account's required minimum of ten.

Read-only reconciliation proves the exact disabled template was restored, all
three functions have their expected code/configuration and concurrency zero,
and all three permanent attempt rows remain absent. There were zero Lambda
requests, provider calls, provider credential reads or model-budget claims.
The initial runner incorrectly required `UPDATE_COMPLETE`; AWS correctly reported
`UPDATE_ROLLBACK_COMPLETE`. Both stable outcomes now pass the disabled-state
validator only when the exact template and all three actual functions also match.

## Minimal proposed account change

The region's applied Lambda limit is ten and all ten slots are unreserved.
No quota-change request is pending. The reviewed request candidate is:

```json
{"ServiceCode":"lambda","QuotaCode":"L-B99A9384","DesiredValue":11}
```

Destination: AWS account `666730517561`, region `ca-central-1`. Eleven is the
minimum arithmetic requirement under the currently observed ten-slot floor.
AWS must approve the request, and its applied limit and reservation rule must
be rechecked afterward. Approval or the absence of a quota request error alone
does not prove Builder can reserve a slot. Do not remove Builder's reservation
or use unrestricted concurrency as a workaround.

Requested owner approval: merge this fix using the review override and submit
this one quota increase request. It changes account capacity, not the USD 0.25
per-role model budget. No live activation, new signature, provider call or
attempt claim is included in this approval. Do not resubmit an uncertain request;
reconcile the Service Quotas history instead.

The failed change set cannot be reused. Preserve the original signed allowance
and no-invocation evidence. After capacity is available, prepare a new reviewed
change set and check the signed allowance's expiry; expired material must not be
retimed or reused. Any replacement live plan needs explicit approval.

`check_pilot002_capacity.py` performs a read-only preflight before future signing
or activation and exits unsuccessfully when capacity is insufficient. Its floor
must come from reviewed AWS evidence, not a guessed lower number. The preparation
artifacts in this PR contain no quota request execution and no signing capability.
