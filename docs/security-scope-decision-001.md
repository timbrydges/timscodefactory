# Pending owner decision: synthetic demonstration scope

Status: proposed, not approved. No finding is waived and no gate authority is
conferred by this document or the completed execution proof.

## Exact decision requested

Accept the three retained Security findings only for the completed fixed-input,
non-production acceptance demonstration of candidate
`09a758184c890eda200326a18fb166641194e32e`, with contract digest
`sha256:7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa`.
The demonstrated runner is source commit
`50e5473f9dcc9139901a6effa0cced7a459fec46`; its five successful synthetic cases are
bound to signed payload
`sha256:ad1de733c6a17293b245dd7c98b80d2255321ca36416009aed6e58cb33a4752f`.

| Finding | Demonstration control | Residual limitation |
| --- | --- | --- |
| Caller path and symlink access | Exact pinned source, generated paths in a private temporary directory, regular-file checks; no caller-selected paths | The standalone CLI can still open arbitrary accessible paths and follow symlinks. No OS filesystem sandbox is established. |
| Blocking special files | Generated regular files and a five-second process timeout per case | The standalone CLI still has no internal read timeout or special-file rejection. |
| Full input in output | Only built-in public synthetic bytes are used; exported results contain hashes, sizes and verdicts | The CLI still returns all input text as required by the original contract. Sensitive data and general user input remain excluded. |

Approval would record acceptance of those residual limitations for this exact
demonstration and allow that disposition to inform a subsequent restricted
Security gate proposal. It would not change the original contract, label the
findings generally fixed, approve arbitrary inputs, or claim independent AI
Security review. The signed result proves execution provenance and five bounded
checks, not comprehensive security assurance.

This decision authorizes no deployment, fresh invocation, signature, model call,
IAM change, state write, release, scheduled work or unrestricted autonomous
operation. The task remains SECURITY_REVIEW version 14. A future gate must bind
the accepted scope explicitly, use a fresh reviewed authorization and lease,
and preserve production_release_authorized=false. Live gate execution and any
temporary controller permissions must be presented as a concrete separate plan.

If these limits are not accepted, retain the Security hold. Broadening the
candidate or contract would require a separate remediation scope; the original
acceptance contract allows zero remediation cycles. Do not turn a failed or
limited security assessment into a general passing verdict.
