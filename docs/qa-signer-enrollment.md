# QA signing identity enrollment

## Approved and deployed, 2026-10-03

The owner approved the existing QA key for a bounded 24-hour window. PR #312
added exactly that entry; controller version 32, source
`7720bdf4320b3a558db2ea706ca55ac52e4330ce`, now contains the verified registry.
Trust expires at **2026-10-04 03:12:33 UTC** without extending other enrollments.
Verification checked the downloaded deployed ZIP, preserved version 31 and all
existing signer entries, automatic expiry, the disabled controller probe, the
disabled schedule and unchanged QA task version 12. No signing or model call
occurred. Evidence: `factory/evidence/qa-signer-enrollment-live-proof-2026-10-03.json`.

The procedure below records preparation and approval requirements. It cannot
re-enroll or extend this entry without a separate reviewed change and approval.

The Google assessment is ACCEPTED and 18 independent QA cases passed. Their
combined evidence remains unsigned. The controller does not currently trust the
QA bootstrap key for operational receipts at the time this proposal was prepared.

`scripts/prepare_qa_signer_enrollment.py OBSERVATION.json PROPOSAL.json` prepares
an exclusive offline output from clean reviewed source. It does not modify the
active signer registry or make an AWS call. It verifies the pinned bootstrap
challenge signature at its historical issuance time, the completed Google bundle,
and a fresh operator observation of the actual AWS public key and Lambda role.
The observation must be no older than one hour and must identify an enabled
Ed25519 signing key with the previously verified fingerprint. An observation is
operator evidence, not a signed AWS attestation or permission grant.

The proposed trust change is exactly one added identity:

- Identity: `qa_engineer_service`.
- Existing role: `arn:aws:iam::666730517561:role/tims-factory-review-qa`.
- Existing key: `arn:aws:kms:ca-central-1:666730517561:key/71cb555e-37e8-44ec-b638-86072e3231c6`.
- Fingerprint: `sha256:2a3b220725f75ef8c7b292e610718861292cf406b157bbb658faada97143fd17`.
- Maximum trust window: 24 hours from activation; existing signer entries remain unchanged.

Explicit owner approval is required before applying this operational trust change:
the previous bootstrap approval covered identity verification, not enrollment.
This adds a trusted identity at the registry level; it is not by itself restricted
to one candidate. Existing role, fresh lease, task, source and evidence checks must
still constrain every operational receipt. Enrollment alone cannot issue a lease,
turn an identity challenge into a verdict, or advance the task.

After approval, repeat the read-only key observation and regenerate the proposal
from the exact reviewed source with a fresh 24-hour window. Compare the current
registry bytes with `current_registry_sha256` before applying the single-entry
change. Stop if another signer or registry setting has changed. Deploy controller
trust through the normal reviewed package procedure and verify the enrolled
fingerprint and expiry. Do not enroll Security or grant any new IAM/KMS rights.

This proposal includes zero model calls, signing calls, new keys, IAM changes,
task writes or release authority. A trusted QA publisher, executor provenance,
fresh QA lease and controller verification remain separate requirements. The
consumed Google allowance stays closed and the broker stays blocked.
