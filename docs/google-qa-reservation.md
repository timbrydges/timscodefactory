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

Google's thinking guide documents a combined thought/output cutoff for the
Interactions API's `max_output_tokens`. The current Factory request uses the
generateContent API. Its reference describes `maxOutputTokens` as the response
candidate limit. Do not silently treat an Interactions-specific statement as
qualification of this request's combined billing envelope. The parser's rejection
of an excessive response happens after provider work and cannot prevent charges.

Resolve that bound, pin fresh pricing and evidence, authenticate a separate
owner-approved generation allowance, then wire broker-only credential loading
after the atomic hold/claim. Never recycle prior Inspector or commissioning
allowances. Existing broker version 1 remains disabled with no generation branch.
Signed QA publication, signer enrollment, fresh QA lease and controller acceptance
remain separate gates; the preflight and local tests grant none of them.

References checked 2026-10-03 UTC:
- https://ai.google.dev/gemini-api/docs/thinking
- https://ai.google.dev/api/generate-content
- https://ai.google.dev/gemini-api/docs/pricing
