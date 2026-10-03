# Pilot 002 one-attempt workflow

Offline composition only, disabled by default. No live handler, default cloud
client, provider adapter, credential loader or signing workflow is added. Tests
use local keys and fake transports; they make no model calls or live claims.

The sequence is: construct the complete provider request, verify the signed
allowance and its deployment-trusted evidence, atomically claim the fixed role
and full USD 0.25 hold, check expiry, load the broker credential, check expiry
again, invoke the transport once, validate provider output and cost, parse the
bound candidate/assessment, and conditionally record completion.

No error path retries a provider, deletes a claim, refunds a hold or moves to a
different attempt key. A failed credential load also consumes the claimed attempt.
An expired approval or backwards clock blocks transmission. Completion is allowed
after a timely request returns, so accounting is not discarded merely because
the approval expired while the provider was processing it. Uncertain completion
requires read-only reconciliation, never reinvocation.

Provider errors are reduced to the failed stage and a no-retry instruction;
credential values and raw exceptions are not propagated. Caller-owned approval
and evidence dictionaries are snapshotted. Adapters receive packet copies.
Model identity, conservative cost ceiling and exact output packet bindings are
checked before completion. Results stay unsigned, unexecuted and without gate
or production authority. Only a response digest is recorded for the raw provider
envelope; future runtime persistence must preserve the returned completion record
for reconciliation without claiming an unsigned result is authenticated evidence.

## Adapter and deployment requirements still outstanding

The injected deployment-owned adapter must construct a deterministic complete
request, send only to its fixed approved provider endpoint with no automatic
retry or redirect, and validate the provider's model identity, finish reason,
all billed usage and actual cost. The workflow does not implement or qualify
these provider protocols. Its transport-invocation count is not independent
proof of an external provider's billing. Credential lifetime and timeout controls
belong to the future reviewed broker implementation.

Fresh pricing/readiness, exact commit-to-tree verification, owner-key enrollment,
live signing authorization, reviewed runtime deployment/access and activation
remain required. No existing model entrypoint, key, consumed approval, historical
ledger or Factory state is altered by this composition. The three providers must
remain disabled until those gates are satisfied and separately approved.
