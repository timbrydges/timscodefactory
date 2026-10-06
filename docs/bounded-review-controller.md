# Bounded review controller composition

`BoundedReviewController` composes authenticated intake, immutable S3 jobs and
scope receipts, generic Lambda role transport, durable dispatch, and signed
result progression. It defaults to disabled and has no Lambda entrypoint.

Deployment owns all three numeric function versions and input digests. Inspector
and QA must agree on the exact factory/task, runtime source, contract, candidate,
test proof digest, and file paths. Separate role bindings select verdict
validation by authoritative state, never by a model's chosen role. Proof must
still be fresh before a tick and before the delegated activation/reservation
guards run. Unknown stages, including SECURITY_REVIEW and RELEASE_READY, stop
without dispatch; this composition cannot authorize security review or release.

The proof bytes and digest must originate from the authenticated exact-main
artifact importer and be pinned in privileged deployment configuration. This
class validates their content and binding; it does not turn arbitrary caller
bytes into authenticated evidence. Unit-test fixtures are not runtime authority.

Live deployment remains separate work: supply fresh signed provider-specific
scope, current pricing, distinct OpenAI/Bedrock/Google routes, immutable role
packages, remote at-most-once budget enforcement, and the final-source test
artifact. Three role names or distinct Python guard objects do not prove three
providers. Keep all historical handoff/recovery claims consumed. The existing
acceptance controller and its historical allowances are unchanged.

Tests exercise both review stages through real Ed25519 result verification and
Moto DynamoDB persistence, including once-only progression. No test calls a
provider or grants live review authority.

`BoundedReviewRoleRuntime` composes the provider backend, fresh result signer and
durable role execution service for an exact deployment-owned job. It defaults
to disabled. It rejects altered events before signing IO, verifies current
scope and dispatch, then checks isolated signing custody and enrollment before
any role execution claim or provider credential read. Signing rechecks current
enrollment after execution; preflight cannot guarantee later KMS availability.
An uncertain provider result still consumes its permanent claim.

Deployment supplies regional no-retry KMS/STS clients. Builder and Inspector
use their existing isolated assumed signing roles; QA uses its existing review
role. The controller receives neither signing nor provider credentials. This
composition does not authenticate arbitrary proof files or expand IAM access.
Deployment must authenticate the exact final
source/candidate and fresh 17-test Docker artifact before constructing it.

Prepare that material with `scripts/prepare_bounded_review_material.py COMMIT
RUN_ID OUTPUT`. The privileged deployment command authenticates the successful
manual main-branch GitHub run and its exact artifact archive before writing
canonical material. It refuses an existing output path. Record its returned
digest in deployment-owned configuration, independently of any invocation event.
Do not accept a file and a caller-provided matching hash as authentication.

`PinnedReviewMaterial.load` checks this trusted digest, exact deployed source,
the fixed fingerprint candidate, and fresh 17-test evidence. It derives the
fixed contract and separate Builder/Inspector/QA job and lease bindings. Public
candidate files are returned as copies; proof and contract are immutable bytes.
The stored `AUTHENTICATED_MAIN_TEST_PROOF` label is descriptive, not a signature
or an authorization: its provenance comes from the privileged importer and
deployment pin. Owner allowance, independent scope approval, current pricing,
live state/lease checks and permanent claims are still required. Never use a
unit-test fixture or historical proof as the deployment import.

`factory_runtime.review_role_lambda.handler` provides a disabled-by-default role
entrypoint. Enabling requires a numeric function version, the exact execution
role, regional no-retry clients, and deployment-owned `BUILD.json`,
`REVIEW_MATERIAL.json` and `REVIEW_ROLE.json`. Configuration pins both review
files with `FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST` and
`FACTORY_BOUNDED_REVIEW_ROLE_DIGEST`; `FACTORY_BOUNDED_REVIEW_ROLE` selects the
fixed role and `FACTORY_BOUNDED_REVIEW_ENABLED=true` explicitly enables it.
The role file contains the fresh signed allowance, pricing, readiness and fixed
credential route. Builder/QA secrets require immutable versions; Inspector uses
its execution-role credentials. Credential reads remain behind permanent send
claims. Errors are redacted and require claim reconciliation, never retries.
This source addition does not deploy functions or grant runtime IAM access.

`factory_runtime.review_controller_lambda.handler` is the separate controller
entrypoint, disabled unless `FACTORY_BOUNDED_CONTROLLER_ENABLED=true`. It accepts
only the fixed factory/task and `mode=bounded-review`, on a numeric version of
the existing autonomy-controller function under its exact execution role.
`REVIEW_CONTROLLER.json` is pinned by
`FACTORY_BOUNDED_REVIEW_CONTROLLER_DIGEST`. It contains the exact activation,
three numeric role function ARNs, stage-specific S3 job versions/digests, and
three fresh signed allowances with pricing/readiness. It contains no provider
credential routes. The activation lasts at most one hour and cannot outlive
any provider allowance. Authenticated material uses the same independent pin
as the role entrypoint.

The controller creates three credential-free provider guards, verifies the
fresh 17-test proof and separate Inspector/QA bindings, then runs one bounded
tick. Signed owner and independent-review intake receipts remain required at
runtime. A configuration hash does not replace those signatures. No KMS or
Secrets Manager client is created by this entrypoint. Deployment, packaging and
exact task/claim permissions remain separate prerequisites; historical claims
and controller activations are not reused.
