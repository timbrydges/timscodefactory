# Authenticate Docker test evidence before controller deployment

`scripts/prepare_review_test_proof.py COMMIT RUN_ID OUTPUT` imports the fixed
`isolated-candidate-test-proof` artifact from a successful manual invocation of
`runtime-canary.yml` on `main` in `timbrydges/timscodefactory`. It reads through
the authenticated GitHub CLI against the fixed github.com repository. The
specified source must match current main, the run and the test proof.

Pull-request runs, forks, failures, duplicate artifacts, incomplete inventory,
expired artifacts and archives whose size or SHA-256 differ from GitHub metadata
are rejected. The archive is read in memory without filesystem extraction and
must contain exactly one bounded `candidate-test-proof.json` file.

The importer reconstructs the expected sandbox request from the pinned candidate
files, fixed test command, immutable image and hardened Docker policy. It checks
the workspace and environment digests, non-root user, disabled network and
diagnostic hashes before requiring all 17 tests and a proof under one hour old.

Output retains the exact proof bytes and GitHub provenance IDs for deployment
pinning. It is an observation from the operator's authenticated API session, not
a self-authenticating signature or Factory gate authority. Deployment must pin
the resulting digest; model output and job input must never choose this file or
provide substitute API metadata. This command performs no AWS mutation, model
call, budget reservation or signed role review. Synthetic unit-test API fixtures
are not live GitHub provenance evidence.
