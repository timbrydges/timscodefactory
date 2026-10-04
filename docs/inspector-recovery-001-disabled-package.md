# Recovery package and disabled deployment preparation

The dedicated packager reads only an explicit allowlist of tracked blobs from a
clean Git commit and Linux Python 3.12 dependencies from the existing hash-locked
requirements. It emits a deterministic ZIP, file-hash manifest, source identity,
ZIP SHA-256 and Lambda code hash. It excludes local environment files, credentials,
activation material and signed allowances. It refuses output inside the checkout
or overwriting an existing artifact. This builder deliberately has no activation
option; a later live-package design requires separate review.

The offline deployment renderer accepts only this inert package, a bounded
archive, the exact recovery object-key prefix and an immutable S3 version in the
existing Factory bucket. It proposes three new resources in a separate stack:

- A recovery-only Lambda function using the new handler, Python 3.12, a
  180-second timeout, reserved concurrency zero and its execution flag false.
- Its exact log group with seven-day retention.
- A dedicated Lambda-assumable role granting only CreateLogStream and PutLogEvents
  for that log group. No model, ledger, secret, KMS or managed-policy access.

There are no public URLs, invocation permissions, aliases, event sources,
schedules, existing-function edits or existing-table changes. The preview
validator accepts only addition of those exact three resources in the fixed
account, region and stack. It rejects changed permissions, enabled concurrency,
mutable package references, active material and incomplete previews.

Tests build repeatable archives with offline dependency fixtures, verify every
manifest hash, exclude an untracked secret fixture, and import the archived
handler in a fresh process to prove its disabled rejection. Separate negative
tests cover dirty source, overwriting artifacts, package limits, source/code
bindings, expanded permissions and changed resources. These do not substitute
for building the locked Linux dependencies and verifying an exact AWS preview.

## Approval scope

Approve source merge after CI and the required owner review override. No AWS
change set, upload, role, function or model call is created by these tools.
After merge, build the reviewed artifact, prepare the exact disabled AWS preview,
and obtain deployment approval before creating its new logs-only role/function.
Provider and recovery-ledger access remain absent until their separate reviewed
approval. Signing integration, a live package, current qualification and a
one-shot shutdown runner remain required before a model call.
