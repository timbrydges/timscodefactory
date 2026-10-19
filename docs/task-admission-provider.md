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
They never apply edits or assert passing tests. Multiple edits to one path are
not supported. New files use empty `old_text` and nonempty `new_text` only for
paths explicitly listed in the frozen input's `missing_paths`. Those paths must
be distinct, within contract scope and absent from the supplied existing files.
The candidate builder requires the complete pinned repository snapshot and
confirms absence before materializing new files. Existing files still require
one nonempty exact source match. Case aliases and parent/file collisions are
checked across the entire resulting repository. New files are non-executable.
Changes to declared missing paths change the provider input digest. This grants
no write access to the actual repository and does not change the default CI
repair workload or its downstream edit restrictions.

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

`candidate_workspace` now applies validated replacements to a fresh disposable
directory, never to the source checkout. It freezes the decision, bounds candidate
size, rejects portable-path aliases and cleans up on success or failure. This is
only the supplied partial source snapshot: it does not fetch or authenticate a
complete repository, install dependencies or implement Bonus Library pagination.

The candidate prepares an existing `SandboxRequest` with the target repository
commit and actual workspace tree digest. Trusted deployment composition supplies
the command, environment, lease and runner identity; provider output cannot
choose them. No adapter is invoked by this module. Before use, deployment must
provide a complete authenticated workspace, a network-disabled sandbox and
separate execution authorization. Temporary directories are not themselves an
execution security boundary; never run candidate commands directly on the host.

Receipt evaluation reuses the existing sandbox binding checks and rejects a
changed candidate. Exit zero yields `TESTS_PASSED_REVIEW_REQUIRED`; nonzero and
timeout remain distinct. Every result is non-authoritative and grants no
progression or release. Offline regressions use receipt doubles, not actual
candidate test execution. Independent review and controller evidence remain
required, even for a successful sandbox observation.

`read_repository_snapshot` now reads the complete tree of an exact local Git
commit, checks each blob against its object ID and bounds the file count and byte
sizes. It ignores dirty/untracked working files and replacement objects, rejects
links/submodules, and performs no fetch, checkout or hooks. A missing object fails
closed. The local object database and repository label must come from trusted
deployment composition: neither a caller-supplied label nor a hash establishes
GitHub provenance or approval. Source executable modes are retained.

Passing that snapshot to `candidate_workspace` retains unchanged tracked files
and requires every provider-context byte to match the pinned source before edits.
Next.js route groups and dynamic path segments are supported without accepting
Windows aliases. The existing Docker adapter can consume the resulting candidate;
offline integration tests inject a process double and verify network-disabled,
no-pull configuration. No real candidate command or provider call is dispatched.
Dependencies must already be available in a separately reviewed immutable image.

Remaining work: actual isolated candidate verification, independent review
semantics for the one-provider development contract, authenticated deployment
composition and owner controls. No live activation, provider call or PR publishing
capability is added to the runner here.
