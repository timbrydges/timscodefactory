# QA executor provenance: prepared, not authorized

QA trust was approved and deployed in controller version 32. That approval did
not authorize signing calls. The next proposal is one invocation of the fixed
18-case QA runner under the existing QA Lambda role, followed by one KMS signature
over its report digest. No model request, Google replay, lease, task transition,
security enrollment or release is included.

`factory_runtime.qa_attestation.handler` rejects by default. Deployment must use
the reviewed clean source, the existing QA package builder and the existing QA
role/key. Preserve old immutable versions and every Security/IAM/KMS resource.
The operator must verify the actual package hash and registry before invocation.

After explicit approval, configure a fresh 32-character lowercase hexadecimal
nonce and a deadline at most five minutes ahead, ending before the enrolled QA
key expires. The exact event contains kind `qa_execution_attestation`, package
source commit, pinned candidate commit and nonce. Required environment values:

- `FACTORY_REVIEW_ROLE=qa`
- `FACTORY_OPERATIONAL_EXECUTION_ENABLED=false`
- `FACTORY_REVIEW_KEY_ARN`: the existing QA key
- `FACTORY_QA_ATTESTATION_ENABLED=true`
- `FACTORY_QA_ATTESTATION_NONCE`: the approved invocation nonce
- `FACTORY_QA_ATTESTATION_EXPIRES_AT`: deadline as Unix seconds

Prepare and verify the package and disabled deployment before starting the short
activation window. Record the activated configuration, invoke synchronously with
SDK retries disabled, and create an exclusive durable operator journal **before**
the invocation. A present journal, timeout, error or uncertain signing result
prohibits retry. This handler has no durable replay ledger; the nonce alone is
not replay protection. Do not expose it as an autonomous signing service.

Immediately disable attestation and set QA reserved concurrency to zero after
the attempt, including on failure. Reconcile the result against the invoked code
hash, cloud role, enrolled public key, source, nonce, candidate, packet, report
digest and approval window. Verify the returned Ed25519 signature independently.
Record actual results; never relabel failing tests as passing.

The signed purpose is `executor-provenance-only`, with `gate_authority=false`
and `production_release_authorized=false`. The report is returned alongside its
signed digest. This does not attest to the Google response or create a QA lease.
Historical signature verification proves issuance, not present authorization.
Fresh QA lease, independent gate publication and controller verification remain
separate work. No cloud deployment or signing invocation is performed by this PR.
