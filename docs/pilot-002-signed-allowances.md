# Pilot 002 exact-request owner allowances

Offline verifier only. No real allowance is issued or signed, no owner key is
read, and no runtime is deployed or enabled. Tests generate disposable local
Ed25519 keys and synthetic request/cost/readiness fixtures. Those fixtures are
not provider pricing or qualification evidence.

The verifier reconstructs the role's packet from the pinned task and baseline,
or the supplied Builder response and candidate commit for a review. It binds the
full provider request bytes, source revision, task, contract, packet, role and
model to an owner signature. A changed request, different reviewer, other source
revision, stale observation or broader signed scope is rejected.

Each allowance permits exactly one provider attempt, no retries, no state writes
and no gate or release authority. Its full USD 0.25 hold matches the fixed-role
attempt store, even if the conservative qualified cost is lower. The allowance
lasts at most one hour and cannot outlive either pricing or readiness evidence.
Pricing evidence lasts at most 24 hours; readiness at most one hour. Zero-dollar
free-tier pricing is deliberately unsupported here until a separate current
billing/data-use qualification is implemented. Historical Google free-tier
approval is not reused.

Trusted owner keys, qualified request cost bounds and readiness records must
come from reviewed deployment configuration, never invocation fields. The
verifier authenticates the owner's signature and evidence bindings; it does not
independently prove provider prices, credentials, model availability or a Git
commit's tree. A future runtime must verify/enroll trusted keys, pin the actual
evidence and satisfy those external checks before supplying this context.

The cost-bound evidence must cover the complete provider-specific request,
including wrappers, schemas, caches and any billed reasoning/output. A packet
byte bound is not a token quote. The positive conservative cost bound must fit
USD 0.25. Repository readiness must verify the exact baseline or candidate tree.
Unqualified flags or a signed digest without the corresponding reviewed
deployment evidence cannot be treated as proof of readiness.

Successful verification returns arguments compatible with the atomic attempt
store; it does not call that store. Future orchestration must claim once before
credential loading, recheck expiry immediately before transmission, parse bound
provider usage/results, retain the hold on uncertainty and never retry a model
call. No current handler calls this verifier. Provider payload adapters, actual
qualification, signing workflow enrollment, runtime activation, constrained
candidate execution and independent gate evidence remain outstanding.
