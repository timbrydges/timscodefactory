# Inspector attempt reconciliation

The approved PR #356 plan was signed once by owner workflow run 37198378725
and executed from merge bdbf3016c18683095221bf9566651454083dd8b1. The single
Lambda invocation started at 2026-10-04T11:21:09Z. Its result was an unhandled,
sanitized error. The runner restored the complete disabled baseline and verified
all three workers at reserved concurrency zero at 11:21:59Z, without errors.

CloudTrail event 8936db64-4880-430a-8669-fb34908ef029 records Converse through
the exact Inspector execution role and approved Sonnet 4.5 global profile at
11:21:37Z, with no provider error code. It reports 5,288 input and 1,269 output
tokens. At the approved standard rates this implies USD 0.034899 of model usage;
it is not an invoice or an accepted runtime cost record. The full USD 0.25 hold
remains. Ordinary AWS runtime/storage costs are separate.

The Inspector ledger is STARTED, permanently HELD, with no completed output.
Builder remains COMPLETE and QA has no attempt. Reconciliation did not modify
any ledger item. Inspector must never be invoked again under this task/role,
including with another signing run, deployment, approval or allowance.

The audit proves provider processing, but cannot identify whether the failure
was in response transport checks, response validation, or completion recording.
CloudTrail has no response body and Bedrock invocation logging is not configured.
The Lambda entry point discarded the workflow's already-sanitized stage. Do not
claim that a specific parser defect, IAM denial or model refusal caused this run.

The accompanying source fix preserves only a fixed workflow-stage enumeration
through the entry-point error boundary. Arbitrary exception text, credentials
and response bodies remain suppressed. Tests cover invalid provider output,
credential failure, forged error text and the unchanged permanent retry guard.
This source change does not deploy, sign, call a provider or alter acceptance.
It cannot reconstruct the missing review or retroactively resolve this attempt.

## Recovery approval boundary

The current Inspector role cannot provide an accepted review. The candidate
therefore remains an unapproved draft; no release, gate receipt, task advancement
or scheduler activation is permitted. QA is a separate unused role, but a QA
result alone cannot replace the missing Inspector review.

A proposed replacement review would require a separately approved recovery
contract, not deletion, refund, expiration or renaming of this attempt. Proposed
scope: the same candidate 09c789a902377cb095c20abae89459c4cec3e89e, one Inspector
Sonnet 4.5 call, USD 0.25 maximum allocation, zero retries, no Builder or QA call,
no gate or release authority, and automatic verified shutdown. Before any such
call, review a bounded response-retention design, test it offline, deploy and
verify the exact source, refresh pricing/readiness, and approve an exact signed
plan. The current USD 0.25 Inspector hold remains consumed independently.
This proposal grants no recovery authority and is not an executable allowance.
