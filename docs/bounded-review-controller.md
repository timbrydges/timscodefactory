# Bounded review controller composition

`security_provider_protocol` builds bounded Bedrock requests for the exact two
candidate paths and all security provenance pins. Its strict response parser
retains ACCEPTED or REJECTED reports and findings without granting advancement.
Tool output, incomplete responses, unqualified billing modes, changed bindings
and model-supplied authority fields fail closed. The codec performs no network
or credential access; live transport and backend integration remain separate.

`SecurityProviderClaims` uses the existing permanent table with only the new
security claim key. It conditionally moves RESERVED to STARTED to COMPLETE,
retaining the USD0.25 hold in every outcome. Concurrent or restarted sends,
changed grants and uncertain write responses cannot create another attempt.
This store accepts only internally verified security allowances; it supplies no
signature verification or live access grants. Historical review keys are never
read or modified by its operations.

`SecurityProviderScope` verifies a separate owner-signed allowance for one
security call with a USD0.25 reservation under the approved USD3.50 aggregate
ceiling. It binds exact request bytes, candidate, test proof, QA result and
security scope to `BOUNDED_SECURITY#004#ROLE#security`. Historical three-role
allowances and claims are unchanged. Pricing and readiness still require fresh
deployment verification; this offline verifier does not establish those facts
itself. No live handler, claim writer or provider invocation uses this scope yet.

`BoundSecurityValidator` is a separate, unwired security report validator. It
binds the exact candidate, fresh test evidence, QA result and security scope to
a distinct security input and lease. Deployment must supply authenticated test
and prerequisite verifiers; a matching digest alone is not authority. Only an
accepted report with no unresolved risk findings passes. The model cannot waive
findings or assert release authority. This addition does not extend the
three-role controller, dispatch a security job, or reuse synthetic security
receipts. Signing, scope authentication and at-most-once execution remain
separate prerequisites for a real security stage.

The generic Lambda role transport also recognizes numeric versions of the
existing `tims-factory-review-security` function. Its dispatch lease must name
`deep_security_reviewer_service`; Builder, Inspector and QA leases cannot use
this route. Transport support adds no live function configuration, credentials
or provider allowance. Integration tests use real test signatures and simulated
AWS to verify one security transition, replay handling and uncertain-send
retention. The three-role controller still stops before security.

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

Build an isolated ZIP with `scripts/build_bounded_review_package.py OUTPUT`.
This default package has no activation material. The builder requires a clean
checkout and takes Python source and the signer registry from committed Git
blobs; ignored files are excluded. Hash-locked Linux Python 3.12 SDK and crypto
wheels are included, with a per-file manifest and deterministic archive metadata.
`scripts/verify_bounded_review_package.py OUTPUT` verifies the archive and imports
both disabled entrypoints without host site-packages. CI runs this verification.
After all registry checks pass on a main-branch push, CI retains the verified
`bounded-review-runtime` ZIP artifact for one day. It contains no activation
material. Deployment must authenticate the successful run's repository, workflow,
main branch, exact source commit and artifact digest before using the package;
an artifact name alone is not provenance or authorization.

For deployment, additionally supply `--role controller|builder|inspector|qa`,
`--material FILE --material-digest DIGEST --config FILE --config-digest DIGEST`.
Both pins must come independently from the privileged authentication/deployment
process. The builder checks the fresh proof, source binding and signed allowances
offline before installing dependencies. It never obtains signatures or creates
claims, and packaging does not enable execution. Existing output paths are
refused. Keep all generated files outside the checkout.

`factory_runtime.review_permissions_probe.handler` is a separate read-only
pre-deployment handler. It requires `FACTORY_REVIEW_PERMISSION_PROBE_ENABLED=true`,
an exact `FACTORY_REVIEW_PERMISSION_PROBE_ROLE`, and both bounded paid-execution
flags explicitly false. Invoke only a numeric function version with the fixed
event kind `bounded_review_data_read_probe`, exact `source_commit`, and a
64-character lowercase hex nonce. It verifies the execution identity, reads
the fresh task/scope and each permitted permanent claim, and requires them to
be absent. Provider roles also read their own exact execution key. An unapproved
claim read must return AccessDenied; throttling or other errors cannot count as
a denial. Existing record contents are never returned.

The result proves only the observed read access and denied probe key. It does
not prove write permission, authenticate review material, authorize a model
call or advance a gate. It performs no data writes, signing, secret reads or
provider calls. IAM simulation is not a substitute for this live source-context
check. Deploying or invoking this probe does not enable the paid entrypoints.

## Verified bounded run 004

On 2026-10-07, runtime `cd8c06647e2f8b41480ddc53cf17d2fabce69033` completed
one OpenAI Builder, one Bedrock/Anthropic Inspector, and one Google QA call.
Each signed result advanced exactly one stage; the final state is
`SECURITY_REVIEW`, version 7. All four workers returned to concurrency zero.
The three calls reported USD 0.121833 against the approved USD 0.50 reservation.
The aggregate USD 3.25 ceiling and historical consumed claims were preserved.

[The retained proof](../factory/evidence/bounded-review004-live-proof-2026-10-07.json)
binds the runtime, candidate, authenticated 17-test Docker artifact, numeric
Lambda versions, permanent claims and historical signatures. Receipt signatures
were audited at issuance time; the record cannot grant fresh authority.
This run does not authorize security review, release or unattended operation.
