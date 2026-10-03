# Proposed bounded Security validation 001

Status: implementation and local verification only. Live deployment, execution
and signing require a new owner approval. The static attestation authorization
is consumed and must never be replayed.

The existing fingerprint contract requires successful output to contain the
input text. This proposal preserves the exact inspected candidate and all three
static findings. It validates only a closed acceptance harness: five built-in
synthetic fixtures, private temporary files, regular-file checks, isolated Python
3.12 with a minimal child environment, and a five-second limit per process.
The caller cannot supply paths, commands or input bytes. Only fixture hashes,
sizes and verdicts enter the report; raw child output is never published.

This is not an operating-system sandbox, an independent model review, a waiver
of the findings, or proof that unrestricted CLI use is safe. No Security gate
is completed and no production release or autonomous operation is authorized.

## Proposed live scope

1. Deploy the exact reviewed immutable package disabled, preserving the existing
   Security role, key, aliases, old versions, other resources and stack parameters.
2. Within the active Security signer enrollment, enable a configuration with an
   exact source, candidate, nonce and at most five-minute deadline. Invoke one
   synchronous `security_validation_attestation` request, without retries.
   This request attempts each of the five distinct synthetic cases once and
   makes at most one KMS signing call. Failed cases remain failed in the signature.
3. Independently verify the signed result and retained findings. Block concurrency
   and restore disabled flags after the request, including any failure. Preserve
   the exclusive, flushed invocation journal; an uncertain result forbids retry.

No new IAM, model requests, task writes, leases, scheduler activation, Google
broker activation or release is included. The task must remain SECURITY_REVIEW
version 14. Existing QA and controller execution remain disabled. Historical
static provenance is verified at issuance; it grants no current execution rights.

Build from a clean checkout using `scripts/build_security_validation_package.py`.
Prepare an unapplied change set using the deployment helper and actual current
CloudFormation template. Validate the actual proposed template and resolved
parameters, allowing only the named Security function properties and one added
retained version. Record package hash and change-set identity before approval.

The handler is not a durable one-shot service. The operator must create the
exclusive invocation journal before requesting execution and never expose the
handler for general repeated calls. The enrollment must still cover the entire
window; this proposal does not extend it.
