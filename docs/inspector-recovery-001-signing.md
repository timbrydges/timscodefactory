# Exact recovery owner signing

The owner workflow has a separate recovery input and job, mutually exclusive
with every existing owner signing/publication job. It requires main, the fixed
owner actor, the production environment and the first workflow attempt. It uses
the existing owner role and enrolled KMS key; no IAM change is included.

The signer reads only the future committed file
factory/evidence/inspector-recovery-001-signing-candidate.json. This change does
not add that file or a live allowance. A caller must provide the exact human-
approved digest of the complete plan. The strict plan schema binds the recovery
activation, pricing, readiness evidence, allowance payload and KMS key. The
activation must match current reviewed owner enrollment and all recovery package
bindings. At least ten minutes must remain before the signed allowance expires.

Only the recovery allowance kind is accepted, with the fixed separate record,
one call, no retry, full USD 0.25 reservation, bounded failed-response capture,
no task-state writes and no release or gate authority. The old Pilot allowance
cannot be substituted. The signature is verified locally before publication.

The CLI creates an exclusive output marker before signing, configures one SDK
attempt and preserves a stop marker on uncertain failure. The workflow does not
allow reruns. A new workflow dispatch is not an automatic retry: any uncertain
signing result requires reconciliation and fresh explicit approval. This is
signing only and does not read or consume the recovery attempt record, deploy
code or invoke a model. The runtime's permanent conditional claim remains the
single-provider-call guard.

Before dispatch, commit and review fresh plan evidence and obtain approval of
its exact digest. Live deployment and execution require the reviewed shutdown
runner and approval of their concrete package, permissions and change set.
