# Inspector and QA first-generation policy proposal

The exact candidate 09c789a902377cb095c20abae89459c4cec3e89e is published as draft PR 3 in timbrydges/tims-factory-autonomy-acceptance. All 17 generated tests passed on Python 3.12/Linux; the tested merge tree matches the candidate tree.

On 2026-10-04, the separately approved Inspector foundation-model token count returned 5,305 input tokens and Google's count returned 5,169. Each succeeded once with zero generation requests and zero attempt claims. The earlier Inspector global-profile count failed and was not automatically retried. The new count identifier is anthropic.claude-sonnet-4-5-20250929-v1:0; the generation identifier remains global.anthropic.claude-sonnet-4-5-20250929-v1:0. Evidence is in factory/evidence/pilot-002-reviewer-token-counts.json.

## Concrete policy change requiring owner approval

Token counts and metadata do not prove permission or quota for generation. Requiring a successful generation before allowing the first generation creates a circular gate. A new, distinct pilot002_reviewer_first_generation_readiness kind permits the owner to accept this specific uncertainty for Inspector or QA without asserting successful generation access.

The new kind requires model_access_verified=false, model_metadata_verified=true, input_token_count_verified=true and first_generation_failure_risk_accepted=true. Existing exact role/model/source/request/packet bindings, verified credential route and repository binding, evidence digest and at-most-one-hour readiness window remain mandatory. The complete readiness digest remains covered by an owner signature. The Builder-only kind is unchanged, and the new reviewer kind cannot authorize Builder.

The deployment operator must substantiate metadata and count facts from authentic observations. These booleans are not self-verifying evidence and must never be supplied by an invocation caller. A count success alone is not qualified pricing. Fresh rate/output-bound evidence, candidate verification and an exact reviewed deployment still precede any signed allowance. Google's free-tier billing observation, credential binding and data-use requirements remain unchanged, including the five-minute freshness limit.

This accepts the risk that the first authorized reviewer generation can fail or be throttled and permanently consume its attempt and USD 0.25 hold. No refund, replacement call, retry or remediation is permitted. One provider call per role, USD 0.25 per role, the USD 0.75 total pilot ceiling, no task-state writes and no gate/release authority remain enforced. Builder's completed attempt cannot be reused.

## Approval scope

Approve this policy and merging its reviewed PR with the owner override after all applicable checks pass. This permits preparation of exact disabled reviewer packages and deployment/allowance proposals. It does not authorize new owner signatures, generation calls, shared-capacity activation, IAM changes, billing linkage, candidate merge, production release or recurring execution. All AWS workers remain disabled. Those later actions require concrete reviewed previews and separate approval.

Tests cover distinct owner-bound readiness, cross-role rejection, stale/missing/false/type-confused evidence, changed candidate commits, and expanded budget/call/retry/state-write permissions. Existing authorization and runtime tests continue to apply.
