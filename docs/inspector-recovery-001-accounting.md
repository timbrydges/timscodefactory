# Separately approved Inspector recovery accounting

The user approved the budget and preparation scope of proposal
`sha256:66514f7e01488384c8e943812488018751de434659aadf4fb0e9487493ceae8b`.
The recorded scope retains the original proposal and distinguishes this approval
from deployment, IAM changes, signing, or live execution authority.

The additional allocation is USD 0.25 for one Inspector Sonnet 4.5 attempt on
candidate 09c789a902377cb095c20abae89459c4cec3e89e. Together with Pilot 002's
original USD 0.75 allocation, the ceiling is USD 1.00. Existing holds remain
consumed. Ordinary AWS infrastructure charges are outside model allocations.
No additional Builder or QA call, candidate modification, release, gate receipt,
task advancement or scheduler activation is authorized by this recovery scope.

The new accounting primitive uses only
`tims-factory-inspector-recovery-001-attempts` and its one fixed Inspector record.
It cannot select another role, table or record. It checks the exact scope-file
hash and candidate, records source/request/approval/pricing bindings, and claims
the full USD 0.25 with a conditional insert. A new source, approval, date or
request cannot reopen that record. Completion is conditional on its original
approval and request, the held allocation, and the recorded maximum quote.
Failure and uncertain writes are never retried or refunded.

This primitive is disabled by default and has no production caller. Enabling it
is not authorization: the future isolated runtime must first authenticate the
exact signed allowance, pricing, readiness and request. It must use a client
configured for one SDK attempt. No existing Pilot 002 module or record is changed.

The offline renderer proposes one encrypted, deletion-protected DynamoDB table
with Retain deletion/replacement policies and no TTL. It grants no IAM access
and creates no Lambda, scheduler or provider route. Its preview validator accepts
only addition of that exact table in the fixed account/region/stack, rejecting
changes to existing resources or incomplete paginated previews. No AWS preview
has been created or executed in this change.

Tests cover concurrent claims, replacement-approval refusal, old-table isolation,
invalid candidate/quote/freshness, uncertain writes, completion bindings, changed
scope, disabled defaults and table-preview expansion. Existing Pilot 002 tests
continue to enforce its original three permanent records.

## Next approval and remaining work

Approve source PR merge after all CI passes, including the required owner review
override. This grants no deployment or invocation authority. After merge, prepare
the exact AWS preview and isolated signer/runtime integration for review. The
future execution plan must pin source and candidate, preserve bounded failed
review responses, use fresh provider pricing/readiness, and verify shutdown on
all outcomes. Neither this accounting primitive nor the budget approval may be
used as a substitute for the separately approved exact live allowance.
