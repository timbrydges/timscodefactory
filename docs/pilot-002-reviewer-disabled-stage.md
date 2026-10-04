# Stage both reviewers while disabled

PR #352 merged as d9c75eb8b59c3c6bda508557224fd92354f8d34c, approving the distinct reviewer first-generation readiness policy. This deployment proposal contains that reviewed code but no activation document or signed allowance. It does not make a model request.

## Exact prepared artifact and AWS preview

- Source: d9c75eb8b59c3c6bda508557224fd92354f8d34c.
- ZIP SHA-256: 75bed64c6cc4fb6669534eb863c26de033fcf720cbfadcd4ff85341383ac00ee.
- ZIP size: 4,778,429 bytes.
- S3 version: y2Fqxeu2En4f_aksFHkn3tivy1M0dCkK.
- Change set: arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-reviewers-disabled-20261004-001/53c91eb1-f8ce-4e0e-a79c-4564a3cbcaa8.
- Account/region: 666730517561 / ca-central-1.

The complete template, immutable code location, rollback template and AWS resource changes are in factory/evidence/pilot-002-reviewer-stage-preview.json. The preview is CREATE_COMPLETE and AVAILABLE, not executed. Its only changes are non-replacing InspectorFunction and QaFunction modifications: package, handler, timeout, description and source tags. Their handler becomes factory_runtime.pilot002_entrypoint.handler and timeout becomes 180 seconds. Both retain execution_enabled=false and reserved concurrency zero. Builder, IAM, ledgers, schedules and task state remain unchanged.

The package was built from committed Git objects and hash-locked Python 3.12/Linux dependencies. Its BUILD.json matches the approved source. Archive inspection found no activation file or environment file. The source's disabled entry-point check precedes credential reads and provider access. No claim of a live reviewer result is made.

## Requested approval and verification

Approve merging this staging review with the owner override after required checks pass, then executing the exact named change set once. This is a disabled code deployment, not shared-capacity activation or permission for signing/model calls.

Immediately before execution, verify the deployed template equals the recorded rollback template, all three roles are disabled with concurrency zero, and the AWS change set/template still match the validator. Use an exclusive durable execution marker and a no-retry AWS client. Do not repeat an uncertain execute request. Wait for a stable stack result, compare the resulting template, and verify each role's code hash, handler, timeout, environment and concurrency. Success requires the exact new disabled template and code. If AWS rolls back, verify the old disabled baseline and report failure; do not silently call that a deployment success. Keep the record for reconciliation.

No Lambda invocation or generated-code execution is part of this step. The existing completed Builder attempt remains held; the unused Inspector and QA generation slots cannot be consumed here. After verified staging, continue preparing fresh pricing/readiness evidence and exact owner-signed allowance proposals, but obtain separate approval before signing or activating either reviewer.

## Remaining activation gates

Token counts are recorded (Inspector 5,305; QA 5,169), but neither is generation-access proof or final price qualification. The exact candidate remains 09c789a902377cb095c20abae89459c4cec3e89e, draft acceptance PR #3, with 17 passing tests. Future activation must bind this commit and exact request bytes to fresh evidence, immutable activation packages and owner signatures. The first-generation risk acceptance must be explicit in each signed readiness record. The USD 0.25 per-role hold, one attempt per role and no retries remain mandatory.

Inspector generation continues to use the global Sonnet 4.5 profile. Google retains its existing project/secret route and free-tier restrictions, including a fresh five-minute billing observation and data-use acceptance. No billing linkage or unqualified paid fallback is proposed. Shared Lambda capacity would require separate explicit approval for each bounded activation; both reviewers remain at concurrency zero here.
