# Credential renewal preparation

`RenewableProviderCredentialSource` is an offline-tested policy component. It
does not read environment variables, access a secret store, contact an identity
provider, or create credentials. No executable host selects it yet.

An operator-supplied issuer must return a provider-enforced, short-lived
`ProviderCredentialLease`. Wrapping a static API key with a new local timestamp
does not meet that contract. The component cannot independently verify a token's
server-side expiry or scopes; the issuer and its provider mapping must do that.

The default is disabled. Activation binds one exact resolved model target. A
renewal is shared by concurrent requests, retains the issuer's absolute expiry,
and requires more than 210 seconds remaining by default (180 seconds for a call
plus 30 seconds of margin). Network delay consumes that remaining lifetime.
The maximum issued lifetime is one hour. Clock reversal, malformed results,
issuance failures, and cancellation stop the instance without fallback or retry.

This failure latch is process-local. Recreating the object is not permission to
repeat an uncertain exchange. Before live wiring, provide a durable issuance
authorization/attempt ledger, verify the host's trusted identity source and
provider mapping, and obtain the specific live-action approval. The scheduler's
packet authorization alone must not grant identity-provider access. Never place
tokens in schedule packets, receipts, logs, or exception text.

Tests use fake tokens and an injected clock/issuer only. Passing them does not
prove automatic production credential rotation or authorize an exchange.
