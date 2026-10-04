# Exact Inspector first-generation proposal

Status: prepared, unsigned, not executed. PR #354 enabled the isolated reviewer
signing path at `19ef4ee13e3d9f557a454c3bb390f7cffef94a20`; it did not authorize
signing or model execution.

## One approval covers this exact sequence

1. Merge this reviewed change after CI passes, using the owner's override.
2. Dispatch `factory-owner-signing` once on main, role `inspector`, with plan
   digest `sha256:bcfa2b20a50fbea9cf6ffa04463246664f18e1977ee256aa89fef62923c60b3f`.
   Verify and retain the resulting exact allowance and workflow run ID.
3. Run `scripts/run_pilot002_inspector_once.py` once with that allowance and the
   exact approved change set below. It rechecks signature, expiry, unused
   reviewer attempts, immutable package, disabled baseline, available capacity,
   aliases, mappings, schedules, resource policy and function URL before changes.
4. Execute only the previewed Inspector update, verify deployed code/environment,
   and submit one synchronous Lambda invocation. Never repeat an uncertain call.
5. Restore concurrency zero and the complete disabled baseline; verify all three
   workers' code, environment, handler, timeout and concurrency. Reconcile the
   permanent attempt record even after failure.

Change set:
`arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-inspector-live-20261004-001/34612e22-f9a4-4b50-b911-1e48bc4ada7d`

Runtime source: `d9c75eb8b59c3c6bda508557224fd92354f8d34c`.
Package SHA-256: `f752869af62165befe73c843f1fc1791e4d703d81f47bd62117c3cc2ff654975`.
Activation SHA-256: `fac2bb12ea20cb23c8e3f16d3fb7223bc1c0ee7044bd68b9d627e96bc817252c`.
Request digest: `sha256:28d292a891a23de0ce6786b758f4d9d1982f8cbf744549a6513514c76233ae0a`.
Candidate: `09c789a902377cb095c20abae89459c4cec3e89e`, acceptance draft PR #3.

The unsigned package is uploaded and the change set preview is CREATE_COMPLETE /
AVAILABLE. Exactly InspectorFunction changes, without replacement. No IAM,
Builder, QA, ledger, schedule, candidate merge or release change is proposed.

## Cost and first-attempt risk

The official AWS pricing UI, with Anthropic / Global Cross-region Inference /
Canada (Central) selected on October 4, shows USD 3 per million input tokens and
USD 15 per million output tokens for Claude Sonnet 4.5. The identical messages
and system input were successfully counted at 5,305 tokens. The conservative
32,768-input and 4,096-output bounds give USD **0.159744** maximum model cost.
The permanent USD **0.25** hold still applies, with one call and zero retries.

Sources: [AWS pricing](https://aws.amazon.com/bedrock/pricing/),
[CountTokens semantics](https://docs.aws.amazon.com/bedrock/latest/userguide/count-tokens.html),
[maxTokens response bound](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InferenceConfiguration.html).
The exact request has no tools, cache controls or extended-thinking configuration.
The cap covers the model request; ordinary AWS storage/runtime costs are separate.

The live audit found the profile ACTIVE, the reviewed IAM policies unchanged,
both reviewer attempts absent, and all three workers disabled. Counting and
metadata do not prove generation access. Approval explicitly accepts that the
first generation may fail and permanently consume the Inspector attempt/hold.

The account has ten shared Lambda slots and cannot reserve one while retaining
its minimum unreserved pool. This proposal temporarily uses shared capacity,
without a function-level concurrency-one limit. The atomic permanent Inspector
claim remains the one-provider-call guard; no scheduler or public endpoint is
enabled. The runner restores the disabled baseline in its failure/success path.

## Expiry and exclusions

The exact allowance expires **2026-10-04 04:37:48 UTC** (October 3, 10:37:48 p.m.
Edmonton). Start the runner before **04:27:48 UTC** to retain its ten-minute
activation margin. It will refuse stale material. Do not silently renew the
plan, change the candidate, reuse the Builder attempt, or retry Inspector.

QA remains disabled and unsigned. No Google billing linkage, paid fallback,
Factory state advancement, autonomous scheduling, gate approval or release is
included. An unsigned model review alone cannot approve the candidate.
