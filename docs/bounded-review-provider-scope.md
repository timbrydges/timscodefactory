# Fresh bounded review provider scope and claims

The `bounded-review-001` scope binds one exact dispatch request, complete provider
request bytes, candidate, test proof, source, contract, provider family/model,
fresh qualified pricing and readiness. An Ed25519 owner signature covers those
bindings, a single attempt with no retries, and the existing budget limits:
US$0.25 per role, US$0.75 for this run, US$2.75 aggregate ceiling. It grants no
production release. Historical handoff allowances cannot satisfy the new kind
or task binding.

Pricing/readiness objects must be assembled from independently verified current
evidence by deployment code. Shape validation does not discover current prices,
model access, credentials or provider identity. The later transport must enforce
the fixed OpenAI, Bedrock and Google routes and exact model/body bindings.

`ReviewProviderClaims` targets only the new fixed
`tims-factory-bounded-review-001-attempts` table and three fixed role keys.
The controller and remote role may share the same RESERVED hold only with all
immutable bindings equal. A separate conditional RESERVED-to-STARTED update
must succeed before any send. Competing invocations, process restarts and lost
responses cannot claim another send. Completion records bounded observed cost
and output digest but retains the entire hold. There is no reset, deletion,
refund, retry, dynamic task namespace or TTL facility; deployment must keep TTL
disabled and deny deleting claims.

These are offline authorization and persistence primitives. They create no AWS
table, sign no scope, access no credential, and invoke no provider. A real role
backend must freshly verify scope before using its internal VerifiedAllowance,
enforce remote task/lease controls, and claim send immediately before transport.
This work does not consume the reserved US$0.75 or alter any historical claim.
