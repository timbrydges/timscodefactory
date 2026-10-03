# Pilot 002 Google free-tier qualification

The preceding adapter required a positive paid-rate quote. The earlier Google
integration supports an unlinked free-tier policy, but that historical allowance
cannot authorize Pilot 002. This change adds a distinct zero-dollar qualification
only for the new QA role and its pinned Gemini model, endpoint and task packet.

The qualification requires project `gen-lang-client-0247455615`, no linked billing
account, verified credential-to-project binding, public synthetic fixtures only,
and explicit acceptance of free-tier data use. The billing observation includes
its timestamp and evidence digest. Pricing and the exact owner-signed allowance
expire no later than 300 seconds after that observation. Both token rates must
be zero. Other roles, paid-rate substitutions, stale observations, wrong projects
and missing data-use consent fail closed.

The full qualification, including billing evidence and consent, is hashed into
the signed pricing evidence. Changing even the observation digest invalidates
the allowance. The bound wrapper reconstructs that pricing from deployment-owned
qualification data; invocation fields must not supply trusted billing claims.
The operator must independently verify the account and credential immediately
before signing. This is a bounded snapshot, not continuous billing monitoring.
Linking billing or permitting a paid fallback during the window is outside scope.

The money bound is based on the unlinked free-tier policy, not an assertion that
the request's thinking/output cutoff is qualified. Those qualification flags stay
false. Response token and byte limits still apply for acceptance, and failures
consume the attempt without retry. The permanent ledger still holds the full
USD 0.25 role allocation; a zero usage-derived charge does not refund or reopen
it. The maximum total allocation and three independent providers are unchanged.

## Read-only source check on 2026-10-03

Google lists Gemini 3.8 Flash input and output, including thinking, as free on the
free tier, with product-improvement data use. Its listed standard paid rates are
USD 0.75 input and USD 3.75 output per million tokens through 2026-12-31.
[Official Google pricing](https://ai.google.dev/gemini-api/docs/pricing).
The general thinking guide's hard combined cutoff example uses Interactions;
that section alone cannot qualify this adapter's generateContent transport.
[Official thinking guide](https://ai.google.dev/gemini-api/docs/thinking).
A read-only console check at 2026-10-03T18:31:31Z again showed no billing account
linked to the exact project; its screenshot digest is recorded in
`factory/evidence/pilot-002-provider-readiness-audit-2026-10-03.json`.
That snapshot is audit evidence only, not a production allowance or verified API
key binding. Recheck before signing; never reuse this snapshot after its freshness
window. No billing linkage, generation, deployment or activation occurs in this
change. Credential-project verification, live readiness and owner signing remain
outstanding.
