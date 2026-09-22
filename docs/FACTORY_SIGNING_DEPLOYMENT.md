# Real Factory signing identities

## Reviewable deployment

The deployed stack contains four non-exportable Ed25519 KMS keys, four aliases
and four isolated IAM roles in account `666730517561`, region `ca-central-1`.
The dedicated CloudFormation stack is `tims-factory-signing`; it owns new names
only and does not modify Terraform-managed state, release or product resources.
The template is `infra/signing/keys.cloudformation.json`.

| Signer | Factory identity | Signing role |
| --- | --- | --- |
| Owner | tim_brydges | tims-factory-signing-owner |
| Planner | software_architect_service | tims-factory-signing-planner |
| Builder | engineering_agent_service | tims-factory-signing-builder |
| Inspector | independent_inspector_service | tims-factory-signing-inspector |

Each role can get its own public key and sign with its own key only. Key policies
explicitly deny signing by other principals, including the controller and other
role sessions. Account administrators retain key-policy management, including
Tim's override path. Roles cannot write DynamoDB, deploy products, invoke models,
modify IAM, or obtain private key material. Each trust policy binds the existing
production environment, exact repository IDs, main branch, distinct workflow name
and Tim's immutable actor ID. This initial trust is for owner-triggered identity
verification; autonomous service trust is a later explicit change.

## Costs and authorization

AWS lists US$1 per customer-managed KMS key per month, prorated hourly: **US$4 per
month for these four keys**, plus metered KMS API requests. Asymmetric signing and
public-key requests are not covered by the symmetric request free tier. This is a
new Factory expense; existing Bonus Library approvals do not fund it.

Source checked 2026-09-22: https://aws.amazon.com/kms/pricing/

Tim executed the approved change set on 2026-09-22 and supplied CloudShell
output showing CREATE_COMPLETE. Four keys now exist and incur the approved charge.
The first verification is four manual workflows, each with two public-key reads,
one successful signing call and three expected cross-role signing denials. Each
workflow disables SDK/CLI retry attempts beyond the initial call. No model calls,
operating-task approvals, provider allowance or continuous worker are enabled.

Keys use retention on stack deletion to preserve verification history. **Deleting
the stack does not delete its keys or stop key-storage charges.** To retire them,
disable the relevant signer, preserve its public evidence, then have Tim explicitly
authorize scheduling key deletion with the configured 30-day recovery window.
AWS does not charge key storage while a key is scheduled for deletion.

## Approved deployment and live verification

Tim approved this exact deployment and the US$4/month plus metered KMS request
charge on 2026-09-22. The authorization audit is
`factory/evidence/signing-deployment-authorization-2026-09-22.json`. Do not request
the same cost approval again. The earlier access blocker in that historical audit
was resolved by Tim running the prepared commands in his authenticated CloudShell.

Live evidence is `factory/evidence/signing-verification-2026-09-22.json`. All four
workflows passed on main at `f58711eec4cf026ef5ff12fba43433ce628aba8d`: four own-key
signatures and twelve cross-role AccessDeniedException results. Public keys match
Tim's stack outputs. Their fingerprints and historical challenge signatures were
also verified locally. Artifact archive digests are recorded from GitHub; the
JSON proofs were recovered from visible job logs, not downloaded archives.

GitHub password confirmation completed and the saved
`FACTORY_SIGNING_CANARY_ENABLED` value is false. All four runs have finished.
There is no schedule, and dispatch remains restricted to Tim on main. The trusted
registry remains disabled pending human review of these exact public keys.

The deployment procedure below is retained for audit; do not recreate this stack
or repeat the verification without a specific reason.

1. From a clean checkout of the approved commit, run
   `python scripts/prepare_signing_changeset.py` in authenticated AWS CloudShell.
   This checks the account, validates the template and creates a CREATE change
   set. It never executes it. Review exactly 12 additions and no replacements.
2. Execute that exact reviewed change-set ARN after the cost/deployment approval;
   wait for CREATE_COMPLETE. Stop on any unexpected resource or permission change.
3. Enable repository variable `FACTORY_SIGNING_CANARY_ENABLED=true` and dispatch
   `factory-owner-signing`, `factory-planner-signing`, `factory-builder-signing`
   and `factory-inspector-signing` from main once each. Turn the variable off
   afterwards. All workflows require Tim as actor and accept no arbitrary payload.
4. Each workflow emits a public key, exact key ARN, fingerprint, signed challenge
   and three cross-role denials. Unknown errors are failures, not evidence of
   denial. Preserve all four artifacts and their digests in the Factory repository.
5. Review key/role ownership and actual cloud evidence, then enroll those public
   keys with exact commit references and bounded validity periods in the existing
   trusted-key registry. The canaries emit CANDIDATE_REQUIRES_REVIEW; they never
   silently approve their own enrollment or an operating task.

## Integration boundary

`KmsReceiptSigner` authenticates its STS role, pins the exact enrolled key ARN and
public-key fingerprint, checks key algorithm/usage, checks receipt identity/kind
and lifetime, and verifies returned signatures locally. It uses canonical JSON,
`ED25519_SHA_512` and `MessageType=RAW` to preserve the existing Ed25519 verifier.
Receipts exceeding KMS's 4096-byte raw-message limit are rejected before signing;
large artifacts must be referenced by digest, not embedded or silently prehashed.

The signing adapter is not a general public endpoint. Its trusted role workflow
must authenticate and review the exact receipt before invoking it. Cryptographic
identity proves who signed, not whether a plan, implementation or review is good.
Real independently executed role services, a fresh operating contract/provider
budget, automatic state progression and unattended scheduling remain unfinished.

Protocol sources:
- https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html

## Validation status

CloudFormation lint passed, including resource and IAM schema checks. A clean
standard-library Python import passed. Unit tests verify real OpenSSL Ed25519
interop through a simulated KMS boundary, role/key/fingerprint mismatch rejection,
oversize/lifetime checks, cross-role denial handling and least-privilege template
bindings. These are local tests, not claims of live KMS custody verification.

The AWS console was unreachable during preparation, but Tim subsequently deployed
the stack and the live signing checks passed. The existing AWS controller role
retains its original permissions. Real role execution and unattended scheduling
remain separate unfinished Factory work; successful signing checks do not prove
an autonomous Factory run.
