# ADR-0001: Phalanx Selective Integration Boundary

- **Status:** Accepted
- **Decision date:** 2026-09-07
- **Owner:** Tim Brydges
- **Factory:** Tim's Software Factory
- **Upstream evaluated:** `usephalanx/phalanx`
- **Pinned audit snapshot:** `2c0b923d8bd31125c507f70cbb3f53e883dbac63`

## Context

Tim's Software Factory and Phalanx solve overlapping problems: multi-agent planning, implementation, review, QA, CI repair, execution isolation, recovery, and auditability.

The Factory already has stronger authority boundaries for its intended operating model: deterministic controller-owned state, role-scoped leases, provenance-bound evidence, explicit separation of author/reviewer identities, GitHub OIDC release authority, immutable/versioned release storage, audited owner override, and owner-only rollback.

Phalanx has substantially more runtime machinery in areas the Factory has not yet fully implemented, especially sandboxed execution, CI reproduction and repair, heartbeat/stuck-task handling, replay, telemetry, and structured handoffs.

The adopted strategy is therefore selective reuse rather than a fork or a clean-room reimplementation.

## Decision

Tim's Software Factory remains the authoritative control plane.

Phalanx-derived code may be used only as a subordinate execution/runtime capability behind explicit Factory adapters. No Phalanx-derived component may become an authority source for Factory state, identity, approval, release, or rollback.

The integration direction is:

`Factory Controller -> leased Factory role -> runtime adapter -> Phalanx-derived capability -> evidence/proposal -> Factory Controller`

Never:

`Phalanx-derived capability -> authoritative Factory state/release`

## Non-negotiable trust boundary

1. **Authoritative state remains Factory-owned.**
   - Only the Factory Controller and the Factory Owner may mutate authoritative Factory state.
   - Phalanx Postgres models, state machines, queues, or approval records may not replace or shadow authoritative Factory state.

2. **Factory identity and leases remain authoritative.**
   - A Phalanx-derived runtime receives only the authority required for the current leased task.
   - Runtime code must not invent, extend, refresh, or transfer its own authority.
   - Expired or revoked Factory leases immediately invalidate runtime authority.

3. **No Phalanx credential model is imported as authority.**
   - No shared application-level GitHub token is accepted as the Factory authorization model.
   - No long-lived AWS access key/secret pair is accepted for Factory release authority.
   - Existing Factory OIDC, IAM, environment, and release controls remain authoritative.

4. **Runtime outputs are evidence or proposals, not decisions.**
   - Runtime results must be bound to task ID, producing role/identity, lease ID, source commit, artifact digest, and required verification metadata.
   - Only the Factory Controller may consume that evidence to advance automated state.

5. **Release and rollback remain Factory-owned.**
   - The existing provenance-verified GitHub Actions OIDC release path remains the only compliant automated production release path.
   - Tim retains ultimate audited release authority.
   - The existing deterministic, owner-controlled rollback path remains authoritative.

6. **Author/reviewer independence is preserved.**
   - Imported runtime code may not weaken provider/identity separation or permit an agent to approve its own work.
   - A Builder-side verifier is not a substitute for the independent Inspector, QA, or Security gates.

7. **Failure is fail-closed at the adapter boundary.**
   - Missing provenance, malformed evidence, timeout, unknown runtime state, stale lease, failed sandbox verification, or adapter exception returns a failed/stalled result.
   - It must never be translated into approval or a successful Factory transition.

## Integration policy

Phalanx is an upstream implementation source, not a framework dependency that controls the Factory.

For every imported or adapted component:

1. Pin the upstream commit used for the review/import.
2. Record original file paths and upstream commit in the change.
3. Preserve the MIT copyright and permission notice for copied or substantially derived code.
4. Place adapted runtime functionality behind a Factory-owned interface.
5. Remove or replace direct Phalanx state, credential, approval, release, and deployment assumptions.
6. Add tests proving the adapter cannot bypass Factory authority.
7. Add failure-path tests before enabling real task execution.
8. Run the independent Inspector and normal Factory CI before merge.
9. Re-audit upstream changes explicitly; never auto-track upstream `main`.
10. Prefer extracting small, comprehensible capabilities over importing whole subsystems.

No Phalanx code is copied by this ADR.

## Initial reuse ranking

| Priority | Capability | Decision | Reason |
| --- | --- | --- | --- |
| 1 | Sandbox + CI environment reproduction | ADAPT FIRST | High time/quality leverage; naturally sits below the trust boundary |
| 2 | CI Fixer verification loop | ADAPT | Strong diagnose/fix/re-run/verify pattern; must emit Factory evidence rather than self-authorize commit/release |
| 3 | Heartbeat + stuck-task/orphan recovery | ADAPT | Valuable for unattended cloud execution; must be controller-observable and fail-closed |
| 4 | Telemetry + failure fingerprints + replay | ADAPT | Reduces repeated diagnosis cost and improves auditability |
| 5 | Structured agent handoffs | ADAPT LATER | Useful evidence structure but not required to start the runtime pilot |
| - | Commander authority/state machine | REJECT | Conflicts with Factory Controller authority |
| - | Shared GitHub credential model | REJECT | Conflicts with scoped Factory identity/lease model |
| - | Long-lived AWS credentials | REJECT | Conflicts with OIDC release architecture |
| - | Phalanx release/approval authority | REJECT | Conflicts with Factory release gates and Tim's owner authority |
| - | Full Phalanx infrastructure stack | REJECT AS DEFAULT | Adds persistent Postgres/Redis/Celery operational complexity before justified by load |

## First implementation slice: runtime sandbox adapter

The first code integration must be a narrow sandbox/CI-reproduction adapter. It is intentionally smaller than the full Phalanx CI Fixer.

### Adapter responsibility

Given a Factory-authorized execution request, the adapter may:

- create an isolated ephemeral workspace;
- materialize the specified repository/commit;
- detect the project's supported test/build environment;
- execute an allowlisted deterministic command with bounded CPU, memory, disk, network, and wall-clock limits;
- capture stdout/stderr, exit status, timings, environment fingerprint, and resulting artifact hashes;
- destroy/reap the workspace after completion or timeout;
- return a normalized evidence payload to the Factory.

### Adapter prohibited capabilities

The adapter may not:

- mutate authoritative Factory state;
- issue or renew leases;
- approve gates;
- merge pull requests;
- release or roll back production;
- access Factory production release credentials;
- silently fall back from sandboxed execution to unrestricted host execution;
- treat a timeout, missing tool, missing dependency, or infrastructure failure as a passing test.

### Minimum output contract

The normalized result must distinguish at least:

- `VERIFIED_PASS`
- `VERIFIED_FAIL`
- `INFRA_FAILURE`
- `TIMED_OUT`
- `POLICY_DENIED`

and include sufficient provenance for the Factory Controller to bind the result to the exact task, lease, source commit, command, environment, and artifacts.

## Acceptance criteria before any Phalanx-derived runtime code is activated

- [ ] Adapter interface and evidence schema are committed.
- [ ] Controller rejects runtime evidence with missing/invalid task, lease, identity, commit, or digest binding.
- [ ] Expired/revoked lease test passes.
- [ ] Runtime cannot write authoritative state directly.
- [ ] Runtime has no production release credential path.
- [ ] Sandbox escape/fallback tests fail closed.
- [ ] Timeout and orphan cleanup are tested.
- [ ] Repeated cleanup is idempotent.
- [ ] Deterministic test failure cannot be reported as green.
- [ ] Upstream provenance and MIT notice requirements are satisfied for any copied code.
- [ ] Independent Inspector review passes.
- [ ] Existing Factory preflight, state-machine, release-control, and rollback tests remain green.

## Consequences

### Positive

- Retains the Factory's stronger trust and release architecture.
- Avoids rebuilding mature runtime ideas unnecessarily.
- Reduces remaining engineering time and AI/API spend.
- Allows runtime pieces to be replaced independently as better implementations appear.
- Limits inherited Phalanx operational complexity and security assumptions.

### Negative

- Requires adapter work instead of a simple fork.
- Some Phalanx modules will need meaningful refactoring to remove direct state/credential assumptions.
- Upstream improvements are not automatic; each adopted update requires review.

These costs are intentional. They buy isolation between third-party runtime machinery and Factory authority.

## Next action

Implement the Factory-owned sandbox adapter contract and tests **without importing Phalanx code yet**. Once that seam is proven fail-closed, evaluate the smallest Phalanx sandbox/environment-detection modules that can be adapted behind it.
