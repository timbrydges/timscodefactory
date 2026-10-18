# Generic task queue: first offline slice

`LocalTaskQueue` persists task routing pins in a local SQLite database.
`GenericTaskRunner` claims one entry and calls a deployment-supplied existing
`AutonomousScheduler`. It does not load adapters from task data, create a timer,
authorize spending, renew enrollment, or grant task execution authority.
The runner defaults disabled and a new queue defaults paused.

An entry represents one scheduler tick, not an entire completed project.
`TICK_COMPLETED` means the scheduler advanced, had already advanced, or reached
release readiness. `REJECTED`, `STOPPED` and `NEEDS_RECONCILIATION` remain distinct.
`enqueue_plan` atomically registers an immutable three-stage development chain.
Each successor becomes claimable only after its predecessor reports ADVANCED or
ALREADY_ADVANCED. Rejection, uncertainty, interruption and release readiness do
not unlock successors. There is no recovery retry, release or PR publication.
The deployment must still supply authenticated intake, budget enforcement,
provider adapters and exact task activation through the existing scheduler.

Claims are transactional across connections to the same local database. A crash
after claiming leaves `STARTED`; reconnecting or re-enqueueing the same entry never
resets it. A pause blocks new claims, not an already-started external effect.
Remote worker/adapters must enforce their own pause and authorization checks.
The local database and scheduler resolver are trusted operator inputs, not
multi-tenant or distributed services. Different entry IDs do not supersede the
existing scheduler's authoritative dispatch ledger or make consumed calls reusable.

The plan pins the target repository and commit separately from the Factory source
commit. Every stage binds the exact task-specification byte digest, activation,
task identity and expected authoritative state. Re-admitting an identical plan
does not reset entries; changed plans or entry collisions fail atomically.
Admission is a trusted local operator operation, not cryptographic approval.

The first task specification is
`factory/projects/bonus-library-pagination/task.json`. It requests a real feature
but is preparation data only. Its target commit is pinned to
`ef88df95bc3f046d080af51e3654d2259759072b`; live allowances and executable approvals
are absent. The actual Bonus Library code has not been modified by this slice.

Offline tests cover two task identities using one runner, concurrent claims,
crash persistence, pause/resume, uncertain outcomes, pin mismatches, rejection
reporting, and integration with the existing scheduler's pause/expiry gates.
No cloud clients, provider calls, production signatures or paid operations are
used. SQLite persistence is not proof of AWS deployment or chat-closed operation.

Progression tests use inert adapters and demonstrate implementation, inspection
and QA ticks ending before security. They are not evidence of actual model review.
Queue-only authenticated admission and offline implementation proposals are
documented in `docs/task-admission-provider.md`. Deployment integration,
sandboxed application/testing and owner-visible status remain outstanding.
Credential lifecycle and live activation remain separate.
