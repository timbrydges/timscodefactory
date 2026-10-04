# Recovery live deployment preview boundary

The offline renderer preserves the verified disabled recovery template as the
rollback target. It proposes only a modified RecoveryFunction and one new
RecoveryAccess policy. The role trust, logging policy, log group, timeout,
memory, handler and architecture remain unchanged. It rejects any other
resource change, replacement, permission expansion or baseline drift.

The proposed policy permits PutItem and UpdateItem on only the separate
recovery table and fixed recovery partition key, with the non-null LeadingKeys
condition. Its three Bedrock statements preserve the previously used Inspector
profile/model/region conditions. There is no original-attempt-table, secret,
KMS, wildcard-model or task-state access.

The renderer validates the bounded immutable package metadata against the
activation bytes, pinned candidate/request/scope, enrolled owner, current
qualification and readiness. At least ten minutes must remain. It requires an
explicit shared-capacity flag before proposing removal of reserved concurrency
zero. That input is not proof of human approval: a future exact reviewed plan
must bind the shared-pool choice and the approved package/change set.

This module is offline only. It creates no change set, grants no permissions,
uploads no code and never signs or invokes. Metadata validation does not replace
fetching the exact versioned archive and checking its hash before execution.
The runtime still requires a recovery-specific owner-signed allowance and an
unused permanent recovery record. Its atomic claim prevents repeat provider
calls but does not itself prevent extra Lambda invocations in the shared pool.

Before any live execution, finish the dedicated owner-signing integration and
one-shot runner with verified shutdown to the exact disabled baseline. Obtain
approval for the concrete deployment, temporary permissions, shared capacity
and one recovery call. The original Inspector attempt must never be retried.
