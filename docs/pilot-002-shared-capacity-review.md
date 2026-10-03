# Shared-capacity alternative for one Builder request

This proposal avoids waiting for AWS Support or changing the regional quota.
It requires explicit owner approval of a temporary exception to the previous
one-slot Lambda reservation rule. It does not activate anything by itself.

## Changed control and retained limits

Remove `ReservedConcurrentExecutions` only from the already reviewed Builder
one-call template. Builder then uses the existing shared account pool of ten.
There is no longer a hard function-level limit of one Lambda execution: duplicate
authorized invocations could start concurrently and incur Lambda overhead.
Availability is also shared, so another workload can cause throttling.

The paid provider-call limit remains one. The unchanged runtime verifies the
owner signature and exact request, then performs a conditional DynamoDB claim
on the fixed Builder attempt key before reading the credential or calling OpenAI.
Only the winner can proceed. All other executions fail before credential access.
The row is permanent and cannot be recycled by changing the request or signature.
A failure or uncertain response keeps the USD 0.25 model hold; no retries/refunds.
The model cap does not include ordinary AWS infrastructure charges.

A concurrent workflow regression test exercises competing claims through the real
orchestration and confirms one credential read, one provider request and one hold.
The conditional-write service is mocked in that test; its behavior follows
[DynamoDB conditional puts](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html).
[AWS reserved concurrency documentation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html)
describes its function-level upper bound and the zero-concurrency shutdown control.

## Exact existing authorization

Use the existing owner signature from workflow `37160620999`; do not sign again.
The earlier deployment failed before invocation, and all role attempt rows are
absent. The same reviewed package, activation digest, prompt, model, credential
version, USD 0.25 cap, zero retries and hard expiry remain unchanged.

- Package SHA-256: `85063553e5c5e9fcb046b15be866a98040b2e29c676e9b202906b6722599c884`
- Activation SHA-256: `ba34487e5726356ecde8fd07212ed6aaf7a32292b591ed4018455881d9a4cf7e`
- Allowance payload digest: `sha256:68d4400d84f7a37207680eabe791b18a579855ae8fb2a47c1e6f750f2067cc04`
- Hard expiry: **2026-10-03 23:45:28 UTC**. Start at least ten minutes earlier.
- New change set: `arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-builder-shared-20261003-001/21b12159-e0b6-4cb6-8eca-d3715b7b74b6`

The new preview changes only Builder. It does not change Inspector, QA, IAM,
account quotas, task state, signing keys, recurring schedules or release controls.
The live audit found no Builder resource policy, public function URL, event-source
mapping or EventBridge target. That does not remove existing account IAM users'
permissions; the signature and permanent attempt claim remain mandatory.

## Approval scope and execution

Approve merging this review with the owner override and the specific shared-pool
exception, executing the new change set once, submitting one synchronous Builder
invocation with the existing verified signature, and restoring the exact disabled
template afterward. This is the first provider attempt, not a retry of a sent call.
Do not execute the previously failed change set or the old runner script unchanged.

Before deployment, verify the exact template from `prepare_pilot002_shared_capacity`,
package and activation hashes, signature, expiry, absent attempts and current
disabled baseline. Recheck shared account capacity and the audited invocation
surfaces. The reservation-specific preflight remains correct for reserved mode;
only this explicitly approved exception uses shared mode.

After deployment, require `GetFunctionConcurrency` to have no
`ReservedConcurrentExecutions` field, and verify the exact enabled configuration.
Invoke synchronously once with SDK retries disabled and a durable exclusive
invocation marker. If AWS throttles or returns an uncertain result, do not retry,
switch to asynchronous invocation, or queue another request.

Use a finally block to set Builder reserved concurrency back to zero first, restore
the recorded disabled template, and verify all three roles with `disabled_snapshot`.
That verifier accepts a completed rollback only when actual code, configuration,
template and concurrency all match. Report any shutdown failure immediately.
Store output as untrusted candidate material; no generated-code execution,
reviewer invocation, task transition, candidate merge or release is authorized.

This alternative does not depend on the pending Support case. Leave that case
unchanged; no further quota requests or support-plan changes are part of this run.
