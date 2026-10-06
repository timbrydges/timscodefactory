# Product Spec reviewer custody verification

The approved `tims-factory-spec-reviewer-signing` CloudFormation stack creates
one Ed25519 KMS key and an isolated GitHub OIDC role in account 666730517561,
ca-central-1. The key incurs USD1/month storage plus metered KMS requests.
Its role can read its public key and sign RAW Ed25519 messages with that key.
The key policy explicitly denies signing by other principals.

The manual `factory-spec-reviewer-signing` workflow accepts only Tim's actor ID,
main, production, and first run attempt. It uses a 900-second role session and
disables credential-action retries. The script pins the created key ARN and
public fingerprint, verifies a real Ed25519 identity challenge, and requires
AccessDeniedException for attempted signing with owner, planner, Builder,
Inspector and QA keys. Other failures are not denial evidence.

The artifact is a public enrollment candidate. It is not a scope review, model
verdict, capability, or enrollment. No model calls, state transitions, worker
activation or provider-budget writes occur. The existing scope signer registry
is updated separately from custody verification. Independent semantic review
remains necessary before using this identity for Inspector intake approval.

Enrollment `spec-signer-enrollment-001.json` records the approved identity and
successful main workflow 37496525372, bound to the independently observed AWS
key fingerprint. The public registry accepts this identity for 24 hours from
the recorded custody challenge. Expiry and revocation still fail closed. The
historical KMS adapter and its four original role bindings remain unchanged;
an exact scope-review signer integration is still required for live intake.

The separately approved `ReadBoundedReviewState` inline policy is retained at
`infra/signing/spec-reviewer-state-read-policy.json`. It adds only DynamoDB
GetItem on the bounded-review-001 task partition, with the leading key required.
It was applied directly to the existing role after explicit action-time approval;
it is not part of the original key stack template. Preserve it when reconciling
that stack. It adds no provider-secret access or state mutation permission.

Manual input `state_read_only=true` selects a separate workflow job that proves
an actual consistent read of the allowed task and AccessDeniedException for
another task. The custody/signing job is skipped in that mode. A missing task
is a valid read result, not an instruction to create it. Only existence and
permission metadata are exported; task payloads remain private. Both modes
remain first-attempt-only and have SDK retries disabled.
