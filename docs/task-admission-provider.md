# Queue admission and offline implementation proposals

`AuthenticatedTaskAdmission` verifies a domain-separated owner receipt before
atomic plan insertion. The receipt binds plan ID, target repository/commit,
Factory source, exact specification digest, all three entries and activation ID.
Receipt identity cannot be reused for another plan. Existing unsigned plans
cannot acquire admission retroactively. Identical replay never resets work.

`OwnerAdmissionVerifier` performs Ed25519 verification only. A deployment-owned
loader supplies currently enrolled and unrevoked owner public keys, normally via
`load_trusted_signers`. Jobs cannot supply keys. The service checks receipt time,
maximum 24-hour validity, owner identity, field set and size. It creates no
signatures, keys, enrollment renewals or execution allowances.

The trusted scheduler resolver must be wrapped with `scheduler_resolver` to
recheck the stored receipt, expiry, revocation and exact entry before dispatch.
Direct `LocalTaskQueue` methods remain trusted local preparation APIs, not an
authenticated network service. Do not expose those methods or a raw scheduler
resolver to untrusted callers. No production entrypoint is wired by this change.
Authentication at queue admission does not replace downstream scope, lease,
budget, pause, review or provider authorization gates.

All admission authority flags are false: this receipt is queue-only. The existing
runner and queue still default disabled/paused. An authenticated plan is not a
grant to call a model, consume a hold, change access or release software.

`TaskImplementationProtocol` binds source context to the task contract, target
commit and explicit file scope. It builds a bounded input for the existing OpenAI
adapter's opt-in `task_implementation` workload. The default CI-repair workload
and default disabled provider policy are unchanged. Decisions may request scoped
files, propose literal replacements with exactly one source match, or escalate.
They never apply edits or assert passing tests. New-file creation and multiple
edits to one path are intentionally not supported in this first slice.

The Bonus Library scope now lists the dashboard page, a pagination helper and its
test file. This is an inert specification; the actual product has not changed.
Its new digest invalidates admission/request pins made from the older bytes.

Offline tests use synthetic source text, a strict authentication-boundary double,
fake credentials/pricing and in-memory HTTP responses. The real Ed25519 verifier
is tested for missing keys and invalid signatures; no valid production receipt
is minted or replayed. Positive cryptographic admission with a fresh authorized
receipt remains unqualified. The integrated queue/provider test stops after a
proposal and does not unlock Inspector or QA. Synthetic cost values are not
charges and change no financial ledger or hold.

Remaining work: sandboxed application/testing of proposals, independent review
semantics for the one-provider development contract, authenticated deployment
composition and owner controls. No live activation, provider call or PR publishing
capability is added to the runner here.
