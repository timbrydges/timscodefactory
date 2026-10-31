# Tim's Software Factory — instructions for coding agents

These instructions apply to external coding assistants working on `timbrydges/timscodefactory`. They guide repository work; they do not grant runtime authority, model-spending allowances, production access, or owner approval.

## Mission

Finish the reusable, unattended, owner-controlled Software Factory. The acceptance target is a durable system that can receive an approved software idea, advance it through independent roles and verified gates, survive interruptions, and deliver a tested release with audited owner controls. Bonus Library is an acceptance fixture, not a substitute product roadmap.

## Read the current evidence first

- `README.md`, `docs/FACTORY_AUTONOMY.md`, and `docs/OWNER_AUTHORITY.md`.
- `factory/registry.yaml`, the applicable operating contract, and the affected implementation, tests, and workflows.
- Recent commits, open pull requests, current CI, and retained evidence. Historical pilot successes, fixture tests, and prepared code are not proof of current live activation.
- Identify the *next unfinished Factory capability* from actual code and evidence; do not repeat completed milestones or expand unrelated product features.

## Non-negotiable architecture

- Tim (`tim_brydges`) is the sole human owner. Never introduce a required second human approver or transfer his override authority to an agent.
- Preserve independent Builder, Inspector, QA, and security roles; a coding assistant's own self-review is not independent Inspector evidence. Enforce distinct trusted identities and exact commit, contract, and artifact bindings.
- Authoritative state transitions belong to the trusted controller. Preserve compare-and-swap state, durable leases, immutable evidence, cumulative budget controls, bounded retries, and fail-closed defaults.
- Do not treat signed origin as an accepted review verdict, infer missing approval, reuse spent allowances, silently replay unknown-outcome paid requests, or promote old dry-run evidence to live proof.
- Preserve protected branches, owner-only production release and rollback, and the existing production-gate policy.

## Work with minimal interruptions

1. Within the explicitly approved task scope, investigate, implement, run tests, fix ordinary failures, and prepare a pull request without repeatedly asking to "proceed".
2. Prefer one bounded Factory milestone per pull request. Define the capability, acceptance evidence, and stopping condition in the PR description. Check for concurrent work before changing shared files.
3. Work on a branch; do not push to `main`, merge, automatically release, or silently activate dormant roles. Do not widen scope merely because a related improvement looks useful.
4. If cloud credentials, a fresh allowance, scope expansion, live AWS/provider calls, repository protection changes, or production authorization are needed, stop only at that boundary and specify the one exact owner action required. Continue any independent, offline-testable work first.
5. On failures, report actual commands, results, evidence links, remaining blocker, and next eligible action. Never claim an integration, deployment, or live test passed without its run evidence.
6. Keep secrets out of commits, logs, PRs, and agent prompts. Do not bypass permission checks or disable safeguards to make progress appear green.

## Local validation

Use Python 3.12 and follow the repository's pinned dependency instructions. Before a PR is marked ready, run as applicable:

```bash
python scripts/build_manifest.py
python scripts/validate_registry.py
python scripts/preflight.py --mode static
python -m unittest discover -s tests -v
python scripts/build_manifest.py --check
```

`MANIFEST.sha256` tracks repository files; regenerate and commit it whenever tracked contents change. If a command needs unavailable infrastructure or credentials, record the exact blocked check rather than weakening the test.

## Deliverable format

A focused PR with verified code/tests and a short report: Factory capability addressed; evidence and CI results; unchanged safety boundaries; unresolved prerequisites; next action. Stop when the defined capability is complete or a genuine authorization/dependency boundary is reached.
