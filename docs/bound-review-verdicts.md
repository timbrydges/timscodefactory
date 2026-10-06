# Bound Inspector and QA verdicts

`BoundReviewValidator` is an explicit deployment-owned adapter for
`SignedResultProgressor.review_validator`. It accepts only `factory_review_v1`
JSON with the fixed factory, task, role, source, contract, input, candidate and
test-evidence digests. An ACCEPTED verdict also requires a nonempty rationale,
bounded findings on allowed paths, and no high or critical findings. Extra or
duplicate fields, malformed bytes, stale dispatch bindings and wrong stages
fail closed before checking tests.

`PinnedPythonTestEvidence` checks retained operator test output against the
deployment-pinned artifact digest and candidate file hashes. It requires Python
3.12 on Linux, zero exit status, no credential-bearing environment, no stdout,
the configured test count without skips, and an observation at most one hour
old. The operator must independently authenticate the artifact: hashing a
provider-authored claim is not proof that tests ran. This adapter executes no
candidate code and does not obtain credentials.

The signed-result integration test verifies rejection without a state write,
then one Inspector-to-QA transition after independent tests pass. Replaying the
consumed receipt does not repeat validation or mutate state again. Separate
tests cover QA, changed candidate bytes, failure/skip output, stale artifacts,
wrong runtimes and non-boolean results.

This library is not automatically installed into deployed controllers. Real
activation still requires fresh immutable source/candidate bindings, a trusted
test runner, current signed scope and role leases, and deployment verification.
Specification and security reviewers remain unsupported by this adapter and
blocked by default. No schedule, release, budget, model call or prior claim is
changed by this implementation.
