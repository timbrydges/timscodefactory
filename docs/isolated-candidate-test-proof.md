# Isolated acceptance test proof

The runtime Docker canary now also runs all 17 tests of the pinned acceptance
candidate using `scripts/candidate_test_proof_canary.py`. It stages only the two
digest-verified candidate files into a temporary workspace and passes a fixed
test command to the existing hardened Docker adapter. Execution uses an
immutable Python image, a non-root user, no network, no inherited credentials,
bounded resources and a disposable workspace copy.

The script verifies the sandbox receipt and unchanged original workspace,
rejects redacted or truncated diagnostics, retains the container's Python
version, and creates the artifact consumed by `PinnedPythonTestEvidence`.
It requires 17 passing tests with no skips and verifies the resulting proof
before writing an exclusive output file. CI retains that JSON for seven days.

The CI artifact is test evidence for this fixed candidate only. It does not
authenticate a provider review, sign an allowance, advance a Factory task,
release software or reopen any consumed handoff attempt. A controller must
authenticate the producing CI run and pin the exact artifact digest before
using it for a fresh review binding. A hash by itself is not runner trust.
