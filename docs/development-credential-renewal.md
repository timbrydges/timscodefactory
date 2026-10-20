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

Without a ledger, the failure latch is process-local. Recreating the object is
not permission to repeat an uncertain exchange. The optional
`CredentialIssuanceLedger` binds an immutable approval digest, identity mapping,
exact target, expected scopes, authorization window, renewal interval and total
exchange count. It starts paused and commits each claim before issuer access.
Unfinished, failed or cancelled exchanges block further claims across restarts.
Successful renewals use distinct slots within the same approved allowance.
Cached credentials are also subject to the ledger's pause and expiry checks.
The ledger stores metadata only. It does not authenticate human approval or
verify provider scopes; trusted admission and the issuer must do that. Do not
delete/replace it to recover an uncertain exchange. Its SQLite transactions
coordinate processes sharing the same local ledger, not multiple hosts with
separate copies. Live composition must choose one authoritative ledger.

Before live wiring, verify the host's trusted identity source and provider
mapping, and obtain the specific live-action approval. The scheduler's
packet authorization alone must not grant identity-provider access. Never place
tokens in schedule packets, receipts, logs, or exception text.

Tests use fake tokens and an injected clock/issuer only. Passing them does not
prove automatic production credential rotation or authorize an exchange.
