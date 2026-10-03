# Exact Builder one-call review

The disabled Builder deployment is verified in
`factory/evidence/pilot-002-builder-stage-verified.json`. All three roles have
execution disabled, concurrency zero and no permanent attempt rows.

## Requested approval

Merge this review using the owner review override, dispatch the existing protected
owner workflow once with the exact plan digest below, execute the recorded AWS
change set once, invoke Builder once, then restore the recorded disabled template.
This is one OpenAI GPT-5.6 Sol request for `safe-workspace-fingerprint-001`.
Inspector, QA, task state, release authority and recurring execution remain off.
No signing or invocation has occurred while preparing this review.

The first-generation risk is explicit: metadata and token counting succeeded,
but generation access/quota has not been proven. A denial, timeout, malformed
response or uncertain outcome consumes the one attempt and its permanent USD
0.25 budget reservation. No retries, refunds or replacement attempt are approved.
The qualified request bound is USD 0.212992; the absolute approved cap is USD 0.25.
This scope does not authorize another provider call or another role.

## Exact artifacts

- Plan: `factory/evidence/pilot-002-builder-live-review-candidate.json`
- Plan digest: `sha256:406fd5212d779375d1232d43dd05b7aa3e10ef76a40fba2f74cb58933194ea91`
- Allowance payload digest: `sha256:68d4400d84f7a37207680eabe791b18a579855ae8fb2a47c1e6f750f2067cc04`
- Runtime source: `535233c6e7e7655ef79e885b9c1a164fd7bee1d4`
- ZIP SHA-256: `85063553e5c5e9fcb046b15be866a98040b2e29c676e9b202906b6722599c884`
- Activation SHA-256: `ba34487e5726356ecde8fd07212ed6aaf7a32292b591ed4018455881d9a4cf7e`
- AWS change set: `arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-builder-once-20261003-001/0c690ed6-39cc-4808-86b6-d7c8b99d9dee`
- Exact deployment and rollback templates: `factory/evidence/pilot-002-builder-live-preview.json`
- Hard expiry: **2026-10-03 23:45:28 UTC**. Do not refresh these timestamps,
  substitute artifacts or sign after expiry. An expired plan needs a fresh review.

The candidate readiness record preserves the actual timestamps of prior metadata
and token observations. It does not claim a new credential read or successful
generation. Its deadline is bounded by the oldest current repository/runtime
observation plus one hour, as well as the pricing qualification expiry.

## Execution sequence after approval

1. Recheck merged source, exact plan/package/template hashes, AWS account/region,
   current disabled template, all three zero concurrencies and absent attempt rows.
   Before any future signature, run `PYTHONPATH=src python scripts/check_pilot002_capacity.py --minimum-unreserved 10`
   using the floor in the recorded AWS rejection. Require `CAPACITY_READY`; if AWS
   changes the floor, obtain fresh evidence and review instead of reducing it.
   Require enough remaining time for signing, deployment and a 180-second run;
   stop before signing if fewer than ten minutes remain.
2. Dispatch `factory-owner-signing.yml` on main once, with only
   `pilot002_builder_plan_digest` set to the exact plan digest. Other inputs stay
   empty/false. The workflow permits only the owner actor, production environment,
   main branch and first workflow attempt; other signing jobs are excluded.
3. Download the signed allowance artifact, verify its exact payload and enrolled
   owner signature locally using the real runtime verifier. Never re-dispatch on
   failure or uncertainty. The root CloudShell session must not sign directly;
   existing isolated owner OIDC/KMS permissions are retained unchanged.
4. Recheck freshness, attempt rows and exact change set, then execute it once.
   Verify code hash, activation hash, Builder handler/timeout, enabled flag and
   concurrency one; Inspector/QA must remain unchanged and disabled.
5. Make one synchronous Lambda request with only `kind: pilot002_run_once` and
   the verified signed allowance. Use `total_max_attempts=1` and a client read
   timeout longer than the Lambda timeout. Persist a local exclusive invocation
   marker before submission. The runtime permanently claims its own attempt row
   before reading its pinned existing OpenAI secret version or contacting OpenAI.
6. On success, rejection, error or uncertain response, do not invoke again. In a
   finally block set Builder concurrency to zero first, then restore the exact
   recorded disabled CloudFormation template. If shutdown fails, report it as a
   blocker immediately; signed expiry still bounds execution. Never claim shutdown
   succeeded until the actual function configuration and stack agree.
7. Read back the attempt row, sanitized result and disabled configuration. Preserve
   the response as untrusted candidate material; do not execute generated code or
   advance task state, invoke reviewers, merge a candidate or publish a release.

Only the existing pinned OpenAI credential is read by the Builder after its claim.
No IAM, key enrollment, Google billing, Inspector or QA permissions change.
The new signing code creates an allowance, not a role verdict or release receipt.
