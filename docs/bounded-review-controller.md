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
