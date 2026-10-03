# Google QA reservation preparation

`GoogleQaReservedAttemptStore` is an unwired storage primitive. It atomically
places a spending hold and claims the same fixed attempt key in one conditional
DynamoDB PutItem. There is no interval in which the attempt is claimed but money
is not held. Competing callers and the older attempt-only primitive collide on
the same key. A timeout keeps the outcome uncertain; it never triggers a retry,
refund, deletion, alternate activation key or new claim.

Amounts use integer micro-USD, require a positive reservation at or below the
approved cap, and reject booleans/floats. A conservative storage ceiling of USD 1
is a rejection limit, not an allowance. Approval and pricing digests, expiry
timestamps, source and request hashes are bound into the row. Expiry prevents
new claims; it never expires an existing hold. Completion retains the hold.

The future broker must authenticate the owner's exact authorization and derive
the amount from a verified pricing/output envelope before using this primitive.
Passing a digest or cap is not proof of consent. The original attempt-only path
must not be wired to generation. No runtime path is changed by this preparation.

## Signed allowance and ordered workflow

`google_qa_authorization.verify` now verifies an Ed25519 owner allowance against
deployment-trusted public keys and a deployment-trusted, qualified pricing
envelope. It binds the fixed activation, exact source, candidate, contract,
packet, serialized request, endpoint, model, pricing digest, spending cap,
reservation, lifetime, one provider call and zero retries. Integer arithmetic
rounds the worst-case input plus combined thought/output cost up to micro-USD.
Pricing must be positive and qualified; an observed free tier is not a budget.
The signed receipt cannot outlive its pricing evidence.

`google_qa_workflow.run_once` composes verification, atomic hold/claim, credential
loading, a fresh expiry check, one exact-request transport call, strict response
parsing and completion recording. The transport checks the reserved request
digest before sending. Failures preserve the hold and sanitize diagnostics; they
never reread the ledger to infer permission, refund, retry or switch activation.
Concurrent callers still compete for the same durable key. Completion remains
unsigned evidence with no task-state or release authority.

These functions are not wired to the Lambda handler or a CLI. All dependencies
are supplied by trusted runtime code, never invocation fields. Future runtime
integration must load active enrolled owner keys from its reviewed registry,
pin independently qualified pricing/evidence, use clients with retries disabled,
and provide broker-only credential access after the claim. This change adds no
production allowance, pricing qualification, signing permission or live caller.
The production broker continues to reject every generation event even when its
enable flag is changed. Test signatures use disposable fixture keys only.

## Gated runtime integration

`google_qa_broker_runtime.handler` is the prepared runtime adapter; the deployed
handler remains `google_qa_boundary.handler`. With the flag false, the adapter
delegates to the existing disabled probe. Its enabled branch requires a source-
pinned activation manifest, qualified pricing, a hash-pinned enrolled signer
registry, and an exact source-bound signed allowance before creating AWS clients.
The pricing window cannot outlive the owner's enrollment. No production manifest
or pin exists: `ACTIVE_MANIFEST_SHA256` is intentionally None. Events and environment
variables cannot override it. A reviewed activation change is still required.

After authorization, the adapter requires the exact isolated broker role in the
expected AWS account, uses clients with retries disabled, reserves the fixed
ledger key, and only then reads the exact approved secret ARN/version/AWSCURRENT.
It checks the returned secret identity before transport. Root sessions and other
roles cannot execute it. It contains no signing or task-state-writing client.
Errors are sanitized; uncertain attempts keep their reservations. Tests exercise
the complete adapter with fixture signatures, fake AWS clients and simulated
provider responses, including missing pins, altered files and credential mismatch.

## Verified preflight and billing distinction

The approved preflight completed at 2026-10-03T00:53:57Z using source
`b52a4e439d18289ea3b921b03cdd0ff31ff4086a`. Google returned the exact model
`models/gemini-3.8-flash` and 2,931 input tokens for the complete request.
Two HTTP requests, zero retries and zero generation calls were recorded in
`factory/evidence/google-qa-preflight-live-proof-2026-10-03.json`.

On the subsequent live AI Studio check, the user's account displayed Pro.
The dedicated Factory key's project `gen-lang-client-0247455615` displayed
Free tier and Set up billing; Thought Engine displayed Tier 1 / Prepay.
These are separate observations. No subscription, key or billing setting changed.

## Remaining live gate

Google's thinking guide and its legacy generate-content thinking page describe a
combined thought/output cutoff using the name `max_output_tokens`. The latter
links to the generateContent reference, which describes `maxOutputTokens` as the
response candidate limit. This additional documentation is relevant, but no
production pricing/limit qualification has been approved or installed. The saved
preflight remains unqualified. The parser's rejection of an excessive response
happens after provider work and cannot prevent charges; never promote that
post-response check into a pre-request billing guarantee.

Resolve that bound, pin fresh pricing and evidence, authenticate a separate
owner-approved generation allowance, then wire broker-only credential loading
after the atomic hold/claim. Never recycle prior Inspector or commissioning
allowances. Existing broker version 1 remains disabled with no generation branch.
Signed QA publication, signer enrollment, fresh QA lease and controller acceptance
remain separate gates; the preflight and local tests grant none of them.

## Read-only reconciliation

`scripts/reconcile_google_qa.py --expected-source-commit COMMIT OUTPUT.json`
checks the AWS account and reads the fixed attempt key with a strongly consistent
GetItem and SDK retries disabled. COMMIT is the expected attempted deployment,
not necessarily the current checkout. The output file is exclusive. No secret,
provider, signing or ledger-write operation is available in this path.

Absence is only a point-in-time observation, never permission to call the model.
STARTED remains an unknown outcome with its hold retained, including after expiry.
A COMPLETE row must contain a valid candidate-bound unsigned assessment and usage;
it still grants no gate authority or refund. Legacy claims without a reservation
are reported separately. Wrong source/request bindings, partial holds, malformed
or contradictory evidence and read errors fail closed without echoing raw data.
This checks stored evidence consistency, not authenticated owner consent or proof
that the provider ran. Reconciliation never retries generation or recycles a key.

References checked 2026-10-03 UTC:
- https://ai.google.dev/gemini-api/docs/thinking
- https://ai.google.dev/gemini-api/docs/generate-content/thinking
- https://ai.google.dev/api/generate-content
- https://ai.google.dev/gemini-api/docs/pricing
