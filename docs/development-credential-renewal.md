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

## Injected exchange-response integration

`compose_exchange_credential_source` joins the durable ledger, renewal policy
and a strict response parser. Its exchange callback has no default implementation
and is never called while disabled. It must eventually use an authenticated,
bounded, no-retry transport and the approved identity mapping. The callback also
supplies subject expiry from a trusted identity source; parsing arbitrary JWT
claims alone would not establish that trust.

The parser requires exactly the approved nonempty scope set. A response without
scopes is rejected even though the provider can omit them for an unrestricted
mapping. It derives issuance time from absolute expiry minus issued lifetime,
allows one second for timestamp rounding, and preserves absolute expiry. Tokens
cannot outlive the subject identity. The composed source defaults to the existing
900-second adapter lifetime limit; a longer token is rejected rather than given
an invented shorter provider lifetime. Any change to that policy needs explicit
qualification. Unexpected response fields, including refresh tokens, fail closed.

Protocol reference: [OpenAI workload identity token exchange](https://developers.openai.com/api/reference/workload-identity-federation).
No network transport, identity configuration or executable host selection is
included in this integration.

## Generic host binding

Trusted operator code may pass a `RenewableCredentialBinding` to
`compose_task_host`. The exact `credential_source` approval pin must match its
digest of the issuance authorization, absolute ledger path and fixed renewal
limits. The identity target must match the host's model and selector version.
Both builder and reviewer share that one credential source. Missing or changed
bindings fail before consuming workflow approval; there is no environment-key
fallback for a renewable pin. Changing the ledger path requires new pins.

This pin prevents accidental substitution; it does not protect against a trusted
operator deleting the ledger at the same path. Deployment must preserve and
protect that file. Python callers supply the trusted exchange implementation;
queue data cannot select a plugin, import path or callable. The command-line
entrypoint still supports only the existing environment-key composition until
an approved identity-source implementation is available. Construction does not
read credentials, exchange tokens or unpause the ledger.

## JWT exchange transport

`JWTTokenExchange` accepts an operator-supplied subject source and starts disabled.
It checks the exact issuance authorization before requesting that identity, then
sends one bounded request to the fixed token endpoint. It does not discover
credentials, enable identity federation, or configure service-account mappings.
The source must return a `TrustedSubjectIdentity` obtained through an authenticated
identity provider; checking JWT envelope syntax does not verify its signature.

The exchange uses the same killable-process transport mechanism as model calls,
with a separate fixed route, 64 KiB request/response limits, no redirects, no
proxy inheritance and no retries. A 30-second overall deadline includes subject
acquisition; the exchange HTTP deadline is 20 seconds. Tokens travel through a
private pipe, not command arguments, environment variables or files. Error bodies
are discarded. A durable claim must surround the complete operation, via its
ledger-bound credential source. Failure or cancellation requires reconciliation.

The source interface and transport are implemented, but no live identity source
or CLI activation is configured. Tests mock sockets, processes and tokens;
they do not qualify TLS access, real identity issuance or live provider behavior.

## GitHub subject source

`GitHubSubjectSource` supplies a GitHub job identity to `JWTTokenExchange`.
Trusted host code pins the exact request origin, private repository name and ID,
main ref and workflow file/ref. The origin must be an HTTPS subdomain of
`actions.githubusercontent.com`; its actual job origin still requires
qualification. Only an enabled source with a matching current authorization
reads the two GitHub job request variables. It checks the URL before reading the
bearer and adds the fixed OpenAI audience once. Packets cannot supply this policy.

One GET runs in the killable transport child with a ten-second limit and 64 KiB
response limit. Redirects, retries and error bodies are rejected. The source
checks returned issuer, audience, repository ID/name, branch, workflow and fresh
issuance/expiry claims. Decoding is not signature verification: OpenAI must
verify the GitHub signature and the configured exact service-account mapping.
Invoke this source only inside the ledger-bound exchange so a failed request
cannot be repeated automatically. This implementation creates no identity
provider, mapping, GitHub permission, runner registration or workflow.

References: [GitHub identity requests](https://docs.github.com/en/actions/reference/security/oidc)
and [OpenAI GitHub federation](https://developers.openai.com/api/docs/guides/workload-identity-federation/github-actions).

## Qualifying renewal timing

The attempt and schedule entrypoints accept a trusted Python
`credential_binding` argument. The scheduler carries that same binding into
each admitted attempt. A renewable source pin requires an exact binding match
and a generic execution profile before any Git or Docker command runs; disabled
entrypoints never consume it. Packets cannot construct a binding or select an
exchange transport. The ordinary CLI still has no identity-source bootstrap:
an operator-owned host must supply it after the separate live authorization.

The renewal interval must fit inside the usable token window. For example, a
300-second token with 20 seconds of exchange delay and a 210-second required
remaining lifetime leaves 70 seconds from receipt before renewal is needed.
The interval is measured from the durable claim, so a 90-second minimum interval
fits this boundary; a 210-second interval does not. A shorter approved interval
provides additional margin. The source
rejects such an incompatible token before returning it to a model caller and
marks the issuance uncertain for reconciliation. It never silently lowers the
approved interval. Qualify the expected lifetime and worst-case exchange delay
offline before requesting live exchanges; the runtime check verifies the actual
remaining lifetime. Fake-time tests cover a 180-second builder stage followed by
a fresh reviewer credential within the same two-exchange allowance.
