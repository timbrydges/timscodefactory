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
is unchanged. Independent semantic review and reviewed enrollment remain
necessary before using this identity for Inspector intake approval.
