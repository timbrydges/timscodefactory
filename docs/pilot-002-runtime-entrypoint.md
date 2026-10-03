# Pilot 002 runtime entry point

PR #340's deployed foundation is verified in
`factory/evidence/pilot-002-disabled-runtime-verified.json`. Each role passed one
synchronous package probe and returned to concurrency zero. All three code hashes
and logging-only roles matched the approved template. No provider attempt was
claimed. Lambda reported cryptography 46.0.5 and botocore 1.42.97.

`pilot002_entrypoint.handler` is source preparation for future activation. The
package builder includes it, and the offline probe imports it without executing
it. The builder still advertises the probe-only handler. This change does not
update any Lambda code, handler, permissions, timeout, concurrency or environment.

The new handler rejects requests unless the deployment explicitly enables it,
identifies one fixed role, and pins the SHA-256 of `PILOT002_ACTIVATION.json`.
This bounded, duplicate-key-rejecting file must reside in the immutable deployment
package and match `BUILD.json`. It contains:

- Schema version 1.0, exact source commit and role.
- Fresh provider rate qualification and readiness documents.
- An enabled owner-only public signer registry with reviewed enrollment.
- A fixed credential route: Lambda temporary credentials for Inspector, or an
  exact same-account/region Secrets Manager ARN and immutable VersionId for Builder
  and QA. SecretString is a raw key or an exact single `api_key` JSON object.
- Null review fields for Builder, or exact base64 Builder response bytes and
  candidate commit for Inspector/QA.

Invocation input is exactly `kind: pilot002_run_once` and `allowance`. It cannot
provide a role, adapter, endpoint, credential, price, trusted key or candidate.
The Lambda context must identify the unqualified role function in account
666730517561, ca-central-1, with at least 120 seconds remaining. The existing
30-second probe configuration cannot meet this requirement.

Before constructing cloud clients, the handler verifies the complete request,
qualification, readiness and owner signature. The established workflow verifies
again, atomically claims the permanent role attempt, checks expiry, loads the
credential, sends once, validates the response, and records completion. SDK
clients use explicit regional endpoints, temporary execution credentials, no
proxy discovery and one total attempt. Secrets are loaded only after the claim.
Errors are sanitized and no failed or uncertain attempt is refunded or retried.
Results remain unsigned and cannot change Factory task state or authorize release.

## Remaining activation work

No activation file, live allowance or new enrollment is included. The package
builder accepts an optional `--activation` file, validates it offline, and includes
its exact bytes and digest in the immutable package. A real reviewed activation
file must still be prepared separately. Actual credential ownership,
model access, full-request cost bounds and repository/candidate binding need fresh
external evidence. The readiness document records those observations; the handler
does not itself establish their truth or fetch GitHub. A deployment review must
verify them before the owner signs the exact request.

New own-row attempt-table permissions, exact secret-version access or Bedrock
model access require a separate reviewed AWS change set. Activating the new
handler, increasing its timeout and opening concurrency also require explicit
approval. Signing credentials remain outside these role functions. Nothing in
this source change activates scheduling, automatic retries, merging or release.

Tests exercise the actual signed workflow through all three roles with fake
provider connections, rejection before cloud clients, immutable credential
versions, consumed attempts after credential failure, duplicate configuration
keys, altered deployment bindings, runtime identity and timeout checks.
