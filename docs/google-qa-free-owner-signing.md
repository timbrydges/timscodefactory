# One free-tier Google review

These tools prepare and sign a proposal; they do not authorize themselves or invoke a model.
Obtain explicit owner approval for one Google QA request at zero dollars with no retries.
The older Sonnet allowance is not authority for this request.

Before signing, verify the exact deployed source, package, disabled configuration, and
unused fixed Google attempt ledger. Recheck Google Cloud Billing for project
`gen-lang-client-0247455615`: it must have no linked billing account. Save the observation
and its SHA-256 digest. The signed observation expires within 300 seconds. The broker
validates this owner attestation; it cannot query Google billing itself. Do not link
billing, switch to paid fallback, or treat the unqualified combined output bound as fixed.

Use `prepare_google_qa_free_allowance.py` with the observation JSON and an exclusive
output path. When tools are newer than the deployed package, pass its verified commit
through `--target-source-commit`. Review the exact proposal and record its digest.

Only after owner approval, use an existing isolated `tims-factory-signing-owner`
session with `sign_google_qa_free_allowance.py`, the proposal, a new output path,
`--approved-digest`, and the same `--target-source-commit`. The helper validates the
exact proposal, active enrollment, caller role, public key, and returned signature.
It does not assume a role or expand IAM/KMS access. Its output starts with an exclusive
uncertainty marker; never automatically rerun signing after an error.

The existing `factory-owner-signing` GitHub workflow is the approved role entry point.
Its separate `sign_google_free_allowance` job remains disabled unless
`FACTORY_GOOGLE_FREE_SIGNING_ENABLED` is explicitly enabled after owner approval.
Pass the proposal as base64, its approved digest, and the verified deployed source.
Inputs enter through environment variables, never interpolated shell commands.
The job accepts only the owner actor on main, production environment, first run attempt.
It returns a short-lived signed artifact and never invokes the broker. Disable its
repository gate after the authorized run. Expired or uncertain results do not allow
an automatic signing rerun or a second provider request.

Signing is separate from invocation. Enabling the broker and publishing an enabled
immutable version require the approved one-call procedure. A disabled immutable version
cannot be enabled in place. Invoke only the verified enabled version once, with SDK
retries disabled and an exclusive local journal, then restore the disabled configuration.
Preserve the fixed attempt ledger on every outcome; uncertainty never permits another
request. Google output is unsigned QA evidence, not authority to advance or release.
