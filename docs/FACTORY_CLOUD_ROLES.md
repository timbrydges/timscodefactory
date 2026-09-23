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
It then atomically creates `EXECUTION#<lease>` in a separate execution table,
under a role-prefixed partition, while rechecking state, scope and
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
   Function URLs, bounded timeouts, durable duplicate prevention, and redacted
   operational logs.
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

## Deployment package prepared — 2026-09-22

The first cloud package enables only an `identity_probe` event: a fixed,
short-lived deployment challenge signed by the appropriate enrolled key.
Operational dispatches fail closed. The full service is packaged for subsequent
backend integration; deployment probes are not autonomous role execution.

`infra/roles/functions.cloudformation.json` creates 14 resources: three functions,
three published versions, three execution roles, three 14-day log groups, one
on-demand execution table and an exact-version controller invocation policy.
Functions use Python 3.12 x86_64, 256 MiB and a 60-second timeout. The controller
invokes exact published versions, while durable role-side claims prevent duplicate
execution. Reserved concurrency is deliberately unset because AWS accounts must
retain at least ten unreserved executions and may reject smaller account quotas.
There are no public Function URLs, model permissions, provisioned concurrency or
schedules. Lambda, DynamoDB, logs and artifact storage incur metered AWS charges;
the existing four-key charge is unchanged and no additional keys are created.

Role execution records now live in `tims-factory-role-executions`, partitioned by
role identity. This fixes a deployment problem in the earlier shared-table layout:
partition-scoped IAM could not isolate execution writes from controller state.
Each execution role may read/condition-check only the cloud-role-canary state
namespace and write only its own execution partition in the separate table.
It cannot mutate controller state, approve scope, delete claims, invoke a model,
assume another signing role or sign directly.

The signing stack's new `EnableRoleExecutionTrust` parameter defaults false.
Setting it true adds an exact-principal trust for each corresponding execution
role to Planner, Builder and Inspector signing roles. Owner trust and all key
policies are unchanged. Short-lived signing sessions have no state permissions.

The package includes hash-pinned Linux cryptography dependencies for signature
verification when the Lambda runtime lacks an OpenSSL command. Existing OpenSSL
verification remains the default where available. Source, wheel hashes, ZIP hash,
S3 object version and published Lambda CodeSha256 are bound into the deployment.

From a clean checkout of the reviewed commit in an owner-authenticated CloudShell:

```bash
python3 scripts/build_role_package.py /tmp/factory-role-package.zip
python3 scripts/prepare_role_deployment.py prepare /tmp/factory-role-package.zip /tmp/factory-role-plan.json
```

Preparation uploads the package to the existing versioned artifact bucket and
creates two change sets without executing them. It rejects any role-stack change
other than the exact 14 additions, and any signing-stack change other than three
non-replacing role modifications. It must not replace a key or modify OwnerRole.

With the already-authorized, expected change sets prepared:

```bash
python3 scripts/prepare_role_deployment.py execute /tmp/factory-role-plan.json
python3 scripts/prepare_role_deployment.py verify /tmp/factory-role-plan.json
```

Execution creates the role stack, then enables the exact signing trust. The
verifier invokes each exact published function once and checks deployed code
hash, execution role, returned nonce/source/identity and its signature using the
reviewed public registry. It saves `role-deployment-evidence.json` next to the plan.
If an invocation outcome is uncertain, inspect the saved response and logs before
running verification again; it does not retry automatically.

At preparation time the agent's AWS browser reports Site Unavailable. No deployment
or live Lambda proof is claimed until these commands complete in authenticated AWS.
The owner's instruction for this step was “proceed, approved”; another generic
approval is not required. Never use this deployment approval as a model budget.

## Live identity deployment — 2026-09-22

The corrected role stack deployed from commit
`5ca830c9e2e3d590891f41b31515335edb20ca75`. The verifier completed for Planner,
Builder and Inspector exact version `:1` functions and returned cleanly to the
owner's CloudShell. All three KMS identity signatures verified, with zero model
calls and operational execution disabled. The bounded record is
`factory/evidence/role-identity-deployment-2026-09-22.json`.

The next package adds a `transport_canary` event. It writes a role-prefixed claim
to the separate execution table, produces deterministic output, signs a bounded
`transport_result`, persists it, and returns the identical result on replay. It
does not call a model, execute project work, schedule itself or enable the full
`RoleExecutionService`. `scripts/prepare_role_transport_canary.py` updates the
three functions to fresh immutable versions, repins the controller policy and
verifies identity, signing, durable completion and replay protection live.

## Live model-free transport — 2026-09-22

Tim deployed source `4faff65894a2d95286f3d657e84972ff37a09b03` and the corrected
verifier completed for Planner, Builder and Inspector exact version `:2`
functions. Each role returned a valid enrolled-key signature, persisted a
`COMPLETE` execution record and returned an identical replay result. All proofs
reported `model_calls: 0`; operational execution and scheduling remain disabled.

## Operational boundary probe prepared — 2026-09-23

The Lambda package now includes a Builder-only signed
`operational_boundary_probe`. It attests the exact acceptance task, approved
model target, cost/call/request limits, absence of provider credentials and
disabled operational state without executing work or calling a model.

All three role functions now require the deployment-owned
`FACTORY_OPERATIONAL_EXECUTION_ENABLED` environment variable to equal the
literal string `false`; CloudFormation hard-codes that value and exposes no
parameter that can flip it. Any missing or changed value fails every invocation.
This probe is prepared but not deployed, so it is not evidence of an operational
backend deployment.

The deployment verifier now requires every fresh immutable role version to retain
that exact disabled kill switch. After the three signed, durable transport proofs,
it invokes the Builder-only boundary probe and verifies its signature plus the exact
task, target, model, call, request and cost bindings. The accepted response must
report zero model calls, no role-held provider credential and disabled operational
execution. This verification remains prepared and unexecuted; it does not deploy
the package or satisfy the live operational-backend gate.
