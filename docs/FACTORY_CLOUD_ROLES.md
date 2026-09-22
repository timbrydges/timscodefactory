# Isolated Factory role execution

## Implemented boundary

`src/factory_runtime/cloud_roles.py` connects the existing `DispatchWorker`
protocol to synchronous AWS Lambda invocation. The controller adapter has no
signer and carries no role credentials. Its trusted deployment supplies an exact
numeric function version in account `666730517561`, region `ca-central-1`, named
`tims-factory-planner`, `tims-factory-builder` or `tims-factory-inspector`.
Aliases, unqualified functions, other accounts and arbitrary endpoints are denied.
`lambda_client(session)` explicitly disables SDK retries, bounds network waits,
and uses the regional AWS endpoint. Deployments must limit each function to 60
seconds or less. The controller verifies ExecutedVersion and bounds response
reads; the existing worker verifies the signed identity, dispatch and output.

`RoleExecutionService` is the code executed inside each role function. It loads
state and dispatch from DynamoDB rather than accepting task-supplied authority.
It requires the correct role lease, exact deployed source/input binding, STARTED
controller claim and worker ID, and current owner/reviewer scope signatures.
It then atomically creates `EXECUTION#<lease>` while rechecking state, scope and
the controller claim. A duplicate delivery cannot execute the backend twice.

The role backend must implement check_activation, reserve and execute. Its
reservation uses the same dispatch ID as the controller's cumulative budget
reservation, idempotently; these are not two separate spending allowances.
After reservation the service rechecks scope, activation and authoritative
state immediately before calling the backend. Backend output is bounded bytes;
the service constructs the result receipt itself and signs it through the
role's `EnrolledKmsReceiptSigner`. Generated text never selects receipt identity,
fields, key ARN, endpoint or approval status.

A completed signed response is retained in the execution record. A duplicate
invocation can return that same historical response without new work or signing.
STARTED without a complete response requires reconciliation. Provider failure,
timeout, unknown invocation outcome or a failed result write never resets the
claim. The controller likewise leaves its dispatch STARTED after a lost response.
Neither component advances a development gate or releases a product.

## Verification and deployment status

Local integration tests use simulated Lambda invocation and Moto DynamoDB with
real OpenSSL Ed25519 signatures. They exercise all three roles, a simultaneous
duplicate-delivery race, lost responses and evidence recovery, backend crashes,
revocation, pause after reservation, wrong signatures, forged dispatches,
incorrect function versions, oversized responses and retry configuration.
These tests are not evidence of deployed cloud functions or live model execution.

**No Lambda functions or new IAM permissions have been deployed.** The existing
KMS signing roles still trust only their owner-triggered GitHub workflows. A
Python service identity is not a substitute for verified cloud permissions.

## Remaining work before live activation

1. Package each role with a concrete sandboxed backend and configure a fresh
   owner-approved Factory operating contract and cumulative provider allowance.
   Existing retired-pilot and Bonus Library budgets cannot fund these calls.
2. Prepare and review the deployment: separate execution roles and credentials,
   exact published function versions, controller-only invocation, no public
   Function URLs, bounded concurrency/timeouts, and redacted operational logs.
3. Scope role DynamoDB access to the permitted project and execution records.
   Roles may read state/scope/dispatch and condition-check them; they may write
   only their own execution records, never controller state, owner approvals,
   independent review receipts or another role's results. Preserve all records
   through retries/restarts; TTL deletion must not reopen a completed lease.
4. Bind each role's KMS signing permission to its own enrolled key without giving
   the controller signing access. The existing key policies deliberately deny
   any principal outside their exact signing role, so this requires an explicit
   reviewed infrastructure change rather than silently reusing controller rights.
5. Propagate current key revocations and pause controls to deployments. Run a
   model-free live transport check, then the approved bounded AI task. Verify
   cloud identity, contention, pause and lost-response behavior in AWS before
   enabling scheduling or claiming unattended operation.

AWS API references used for transport behavior:
- https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/client/invoke.html
- https://docs.aws.amazon.com/botocore/latest/reference/config.html
