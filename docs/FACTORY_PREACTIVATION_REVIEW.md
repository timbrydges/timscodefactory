# Factory acceptance pre-activation review packet

Review the immutable PR head that contains this packet, starting from baseline
`a1fd50f5a48588d65352736f4803bb8658271871`. Tim explicitly waived the
independent pre-activation reviewer for this acceptance task on 2026-09-29.
The exception is recorded in
`factory/evidence/owner-review-exception-2026-09-29.json`; it is an owner
decision, not an independent review, an operational activation, or authority
to spend. Keep the substantive checks below as deployment verification tasks.
Tim is the sole human authority; no second human reviewer is required. The
separate `independent_inspector_service` receipt below belongs to an AI role
that must actually inspect the exact scope before its isolated key signs. It
does not have veto power over Tim's audited owner override or stop order. The
owner exception for PR #198 did not fabricate an inspector receipt or change
the normal automated dispatch rules.

## Exact scope and current state

- Task: `deterministic-text-fingerprint` in private repository
  `timbrydges/tims-factory-autonomy-acceptance`, commit
  `fcb4c535d4ea00962b26db14f59e34917ef2389f`, contract SHA-256
  `7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa`.
- Owner allowance: `gpt-5.6-sol`, USD 5 total, USD 0.25 per call, three calls,
  24 hours, no production release. Source:
  `factory/autonomy/operating-contract.yaml` and its owner evidence.
- Pricing quote: `factory/evidence/openai-gpt-5.6-sol-pricing-quote-2026-09-28.json`,
  expires `2026-09-30T05:45:10Z`. The runtime rejects stale pricing. Renew it
  before activation if the review completes later.
- Receipt roles: owner and inspector live canaries passed in GitHub Actions
  runs `36527044416` and `36527291302`; evidence is
  `factory/evidence/receipt-writer-iam-canary-2026-09-28.json`.
- Broker version `:4`, Builder version `:8`, acceptance schedule `DISABLED`.
  Their deployment, credential metadata and disabled probes are in the
  corresponding `factory/evidence/*live-verification*.json` files.
- Merged PR #198 changed only the approved Sol target's policy and catalog
  switches to `enabled: true`; Terra stays false. The exact profile hashes
  are recorded in `factory/evidence/sol-target-technical-enablement-2026-09-29.json`.
- The disabled schedule's `factory_id` input was corrected from `factory` to
  `tims-software-factory` with the guarded input-only Terraform update. The
  AWS canary passed while the schedule remained `DISABLED`, with zero model
  calls. Evidence: `factory/evidence/disabled-schedule-binding-verification-2026-09-29.json`.
- `guarded_operational_role_activation`, `live_controller_runtime_deployment`,
  and `guarded_schedule_activation` remain pending, so the live authorizer
  still denies. The broker and Builder have separate disabled switches. The
  controller has only a disabled probe, and Terraform keeps the schedule
  disabled. No provider call or approval receipt is authorized by this candidate.

## Review before gate closure or deployment

1. Compare the exact task, source, signed scope, reviewer separation, budget
   reservation, replay and unknown-outcome behavior against the owner terms.
2. Review the independent IAM identities and live canary logs. Confirm each
   can write only its own encrypted versioned receipt and cannot read or
   overwrite another role's receipt.
3. Check the broker-only secret lease, no credentials in Builder, no retry,
   pinned broker version, exact endpoint and response validation. Confirm the
   provider request uses explicit-only caching without breakpoints so its
   USD 0.25 worst-case bound excludes cache-write charges.
4. Inspect this target candidate and the later gate-closing diff. The runtime
   scope must remain the exact Sol target, retain the unapproved challenger
   off, preserve Tim-only release authority, and use a fresh quote. This
   candidate alone does not close any remaining gate.
5. Record the owner exception and exact candidate head in deployment evidence.
   CI success or this packet alone does not close any remaining technical gate.
6. Require a guarded live controller canary that verifies the exact
   task, budget, stop conditions, durable state and replay behavior. Verify
   the pinned broker and Builder deployments with their operational switches
   enabled before closing the role gate. Review the schedule enablement and
   its execution role separately, then canary it under the same limits. The
   present disabled controller probe and schedule do not establish these gates.

The repository includes an `AcceptanceController` guard that reloads the
operating allowance and price before a tick, checks the deployment binding,
and delegates to the bounded scheduler. It is implementation preparation only:
the deployed Lambda remains probe-only. `VersionedS3AcceptanceJobSource` can
restore a deployment-pinned stage plan and two exact receipt versions from a
versioned S3 object, checking its checksum, digest, task, stage and bytes. The
separate receipt transport and intake must still verify the owner and reviewer
signatures. Publishing the reviewed jobs and receipts, deploying the controller
with scoped IAM, and its operational canary are still outstanding.

The controller Lambda now has a guarded composition branch for one pinned
Builder stage: it parses deployment-owned activation and job versions before
constructing DynamoDB state/dispatch/budget adapters, the S3 job and receipt
readers, the public signer registry, and a version-pinned Builder executor.
The controller has no signing key or provider credential, and its guard cannot
execute a provider call. The deployed CloudFormation template still hard-codes
`FACTORY_AUTONOMY_CONTROLLER_ENABLED=false`; no operational IAM, reviewed job
publication or live invocation has been deployed or verified. This branch alone
does not close `live_controller_runtime_deployment`.

`scripts/prepare_acceptance_job.py BINDING.json PLAN.json
RECEIPT_VERSIONS.json INPUT CONTRACT OUT.json` now produces the canonical
`IMPLEMENTATION` job bytes after checking the exact task, activation window,
source and contract digests, input digest, lease, scope payloads and two distinct
version fields. It runs the controller's job decoder and IAM bundle renderer
against those bytes. This is offline preparation: the receipt versions must
come from separately authenticated owner and inspector publication under the
same plan digest, and the emitted job has no S3 version until separately
published and verified. Do not treat the output as a signature, review verdict,
live controller deployment, or permission to enable the schedule.

`scripts/prepare_acceptance_inspector_review.py BINDING.json PLAN.json INPUT
CONTRACT OUT.json` prepares the exact material for the separate AI Inspector.
It validates the same activation and scope bindings, marks task bytes as
untrusted, and emits a review request without the caller's proposed verdict
or rationale. It emits no signature, receipt version or model-call authority.
A live Inspector decision and separately authenticated
receipt publisher are still required before job publication.

`scripts/prepare_acceptance_inspector_prompt.py PACKET.json OUT.json` checks
the pending packet's byte digests and renders the exact untrusted input and
contract in a separate user message under an independent inspection system
instruction. Its output is `PREPARED_NOT_INVOKED`: it neither calls Anthropic
nor authenticates a resulting verdict. The retired pilot's Bedrock role and
USD 10 pilot budget do not authorize this acceptance task. Before an actual
Inspector call, establish an acceptance-specific model, fresh price and cost
limit, isolated execution identity, and an authenticated publisher that binds
the model's decision to this exact plan. The existing USD 5 OpenAI Builder
limit cannot silently fund a second provider.

`scripts/prepare_acceptance_inspector_iam.py GET_INFERENCE_PROFILE.json
POLICY.json` renders an unattached policy from a current AWS
`GetInferenceProfile` response in `ca-central-1`. It permits only the exact
global Anthropic profile and its enumerated foundation model, with the
profile condition on model resources. A changed profile requires a new
render and review. This is an IAM candidate only: no role is created, no
policy is attached, and no Bedrock call or receipt is authorized. An
acceptance-specific financial allowance and isolated execution deployment
are still required.

The role template includes an exact Sonnet 5.5 Inspector policy behind
`EnableInspectorAcceptanceIam`, which defaults to `false`. The currently
deployed role has no acceptance invoke permission. The policy matches the
observed global and ca-central-1 foundation-model routes; a future profile
change requires a new review. `scripts/prepare_inspector_acceptance_iam.py`
now provides separate prepare, execute, reconcile and verify phases. Preparation
creates and validates only the exact CloudFormation change set; execution is
explicit and verification requires the reviewed inline policy, unchanged
Builder IAM state, and `FACTORY_OPERATIONAL_EXECUTION_ENABLED=false`. IAM
enablement alone therefore cannot invoke a model. Tim then ran the guarded
prepare, execute and verify sequence against commit
`b9dd94fc865e2d7bd78e34fd480e52d8f391600c`. CloudFormation changed only the
Inspector role and its dynamic Lambda role reference, the exact inline policy
verified, `FACTORY_OPERATIONAL_EXECUTION_ENABLED` remained `false`, and the
verifier made zero model calls. Evidence is
`factory/evidence/acceptance-inspector-iam-live-verification-2026-09-29.json`.
This closes only the Inspector IAM deployment sub-gate; the independent
Inspector budget/runtime and authenticated reviewer publisher remain pending.

Global Sonnet 5.5 pricing observed on the AWS Bedrock pricing page on
2026-09-29 is USD 2.00 per million input and USD 10.00 per million output
tokens from Canada (Central). The separate Inspector price snapshot in
`factory/evidence/acceptance-inspector-pricing-2026-09-29.json` expires in
24 hours. At 42,020 input and 4,096 output tokens its quoted maximum is
USD 0.125; the proposed independent allowance reserves USD 0.25 for one
attempt, with no retry after an uncertain result. The owner-run dummy-text
preflight confirmed there is no usable exact CountTokens path for Sonnet 5.5
in this commercial account: `bedrock-runtime` returned `ValidationException`
and the US East `bedrock-mantle` path returned HTTP 404, with zero model calls
and no task material sent. AWS documents that CRIS-only Claude models may not
support CountTokens on `bedrock-runtime`; the Sonnet 5.5 model card currently
lists its Mantle availability only in GovCloud West.

The budget gate therefore fails closed without pretending to know an exact
token count. `acceptance-inspector-budget-policy-2026-09-29.json` reserves a
fixed 100,000 input tokens plus 4,096 output tokens for any request of at most
42,020 bytes. At the locked USD 2/M input and USD 10/M output rates, that
reserves USD 0.24096 against the USD 0.25 one-call allowance. The conditional
DynamoDB write remains single-use, and an uncertain reservation or provider
outcome permits no retry. This budget fallback authorizes no call by itself.

The reviewer receipt publisher still fails closed for a prepared
`ACCEPTED` plan or possession of the Inspector signing identity alone.
`InspectorReviewRuntime` now supplies the missing authentication path in code:
it verifies the exact prepared request and intake-plan digests, durably consumes
the single conservative budget reservation before one retry-disabled Sonnet 5.5
Converse call, validates provider usage and the bounded structured assessment,
and returns a sealed decision object. Reviewer publication accepts only a sealed
`ACCEPTED` decision bound to the same plan, input and contract digests; rejected,
forged, malformed or uncertain outcomes cannot sign or publish. A provider
transport error occurs after the durable reservation, so a retry fails closed.
This is implementation only until the Inspector operational Lambda composition,
deployment and live canary are separately verified. The owner receipt publisher
remains independently usable.

`parse_assessment` checks a bounded JSON response against the three exact
review digests and rejects duplicate fields or unexpected authority claims.
Its result is untrusted evidence regardless of whether it says `ACCEPTED`;
it cannot sign or publish a receipt. The current Sonnet 5.5 model card lists
`bedrock-mantle` availability only in GovCloud West, which is outside this
account. The observed US East 404 is consistent with that listing. Do not
repeat that probe as though it established a usable counting route.

Claude Sonnet 5 is a possible fallback because its model card lists an
in-Region US East Mantle endpoint with token counting. The separate
`scripts/probe_acceptance_inspector_sonnet5_tokens.py` sends dummy text only
to test this account's no-charge access. It does not select that model or
transfer the Sonnet 5.5 price, policy, or allowance. A successful count probe
would still require a fresh exact price, isolated IAM/budget binding and an
authenticated Inspector runtime before task material or a provider call.
The dummy-text Sonnet 5 probe reached the endpoint but returned HTTP 403 with
`permission_error`: `anthropic.claude-sonnet-5 is not available for this
account`. This is an account model-availability failure; do not infer that
granting `bedrock-mantle:CountTokens` alone resolves it. The observation is
recorded in `factory/evidence/acceptance-inspector-model-access-2026-09-29.json`.
No invocation or task data was sent. The read-only
`scripts/probe_acceptance_inspector_model_access.py` queries AWS's
GetFoundationModelAvailability for exact candidates in the applicable
Regions. It changes no agreement, IAM policy, entitlement or model selection.
The owner-run inventory returned `AUTHORIZED`, `AVAILABLE` entitlement and
region, but `NOT_AVAILABLE` agreement for Sonnet 5.5, Sonnet 5 and Sonnet 4.6.
AWS documents `NOT_AVAILABLE` agreement as access not established. This is a
concrete account-level gate, even though other fields are green. The Haiku 3
entry returned `ValueError` from the exact model-ID check and establishes no
access conclusion. The observation is recorded in
`factory/evidence/acceptance-inspector-agreement-inventory-2026-09-29.json`.
The next read-only `scripts/probe_acceptance_inspector_agreement.py` checks
whether an Anthropic first-use case is on file and whether a public Sonnet 5.5
agreement offer exists. It emits only presence and count; it does not print
use-case contents, offer tokens or signed legal URLs or accept any terms.
The owner-run compact diagnostic found one public Sonnet 5.5 offer and
confirmed that an Anthropic first-use case is present. No agreement was
created, no model call occurred, and no task material was sent. AWS documents
creation of the foundation-model agreement with the public offer token as the
next access step. That owner-controlled terms-acceptance action must not run
without explicit owner confirmation. The repository provides
`scripts/request_acceptance_inspector_agreement.py`, which rechecks the exact
account, model, use-case presence and single public offer, requires the exact
owner confirmation string, and never prints the offer token, use-case contents
or signed legal URL. Tim explicitly authorized the Sonnet 5.5 public model agreement and ran the
guarded request from CloudShell. AWS accepted the request, reported four
`PENDING` observations, then reported `AVAILABLE`; the command made zero model
calls and sent no Factory task material. Evidence is recorded in
`factory/evidence/acceptance-inspector-agreement-activation-2026-09-29.json`.
The post-agreement verification then showed Sonnet 5.5 with agreement
`AVAILABLE`, authorization `AUTHORIZED`, entitlement `AVAILABLE`, and regional
availability `AVAILABLE`. The global Sonnet 5.5 inference profile is `ACTIVE`,
`SYSTEM_DEFINED`, and routes only to the exact regionless and Canada Central
foundation-model ARNs already present in the reviewed IAM candidate. The
unattached policy renderer returned `PREPARED_UNATTACHED`; no model call or task
material was sent. Evidence is recorded in
`factory/evidence/acceptance-inspector-access-profile-2026-09-29.json`.
The next no-charge check is the dummy-text Sonnet 5.5 token-counting probe.

Until the target change and remaining technical gates are recorded,
keep the contract default `DENY`, all operational switches off, and the
schedule `DISABLED`.

The model-free Inspector runtime boundary has now been verified live at source
commit `7ba7ec2eb9f37953e6476d5cdfe13a0e25de9bdd` on Inspector Lambda version
`:10`. The signed proof bound Sonnet 5.5, the separate USD 0.25 one-call cap,
USD 0.24096 conservative reservation, 42,020-byte request limit, authenticated
reviewer-publication requirement, zero model calls, and operational execution
still disabled. Evidence is
`factory/evidence/acceptance-inspector-runtime-boundary-live-verification-2026-09-29.json`.
A live Inspector provider call still requires separate owner spending authority.
