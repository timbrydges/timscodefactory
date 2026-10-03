# Builder cost and first-generation review

The approved token request succeeded once: 2,636 input tokens, HTTP 200, no
generation or attempt claim. Its complete sanitized observation is now retained
in `factory/evidence/pilot-002-builder-token-verified.json`.

Current [GPT-5.6 Sol pricing](https://developers.openai.com/api/docs/models/gpt-5.6-sol)
lists USD 4 per million input tokens and USD 20 per million output tokens.
The documented [output limit](https://developers.openai.com/api/docs/guides/reasoning)
includes reasoning and visible output. Applying these rates to the entire
32,768-token input ceiling and 4,096-token output limit yields USD 0.212992.
The role still reserves USD 0.25 permanently. No unused allocation is refunded
or reopened. This bound uses the reviewed single-turn text request, standard
service tier and explicit caching with no cache markers or tool calls.

`prepare_pilot002_builder_qualification.py` checks the exact request/count hashes,
successful observation, rates and limits, then validates its proposed qualification
through the real disabled adapter. It cannot sign, call a provider, claim an
attempt or deploy. Its expiry is at most 24 hours after the older measurement or
price observation; rerunning it cannot refresh those observations. These artifacts
are review candidates, not permission to generate. Provider/request changes need
fresh review, rather than assuming historical token counts guarantee future use.

## Explicit first-generation policy for owner review

The original readiness format requires `model_access_verified: true`. Successful
model metadata and token counting do not prove generation permission or quota.
Requiring successful generation before the first authorized generation is circular.

A distinct `pilot002_builder_first_generation_readiness` format addresses that
case without claiming verified generation access. It requires:

- Builder role only; Inspector and QA cannot use this format.
- `model_access_verified: false`, `model_metadata_verified: true` and
  `first_generation_failure_risk_accepted: true`.
- Verified credential route and repository binding, plus all original exact
  role/model/task/source/request/evidence bindings and the one-hour freshness limit.
- The owner's signature over the exact readiness digest and qualified pricing.

Changing an existing signed readiness record into this format invalidates its
signature. An absent or false risk acceptance, false metadata/credential/repository
proof, stale record, reviewer substitution or expanded allowance is rejected.
The existing one-call, zero-retry, USD 0.25 permanent hold, expiry, no-state-write
and no-release rules remain mandatory. An access denial, quota failure or uncertain
response consumes the attempt. An end-to-end mocked 403 test proves one request,
one retained budget row, and no second credential read or provider request when
the event is replayed.

The owner is asked to approve this policy and merge the reviewed change. This is
not permission to activate Lambda, sign a real allowance, or make the generation
call. No production readiness record with risk acceptance is created here. The
existing owner public key can be selected from its reviewed enrollment; no new
private key or IAM privilege is needed merely to prepare that configuration.
The next deployment package must still bind fresh external readiness evidence and
be reviewed before the separate exact live action is approved. All workers remain
disabled, and Inspector/QA remain distinct providers reviewing the actual candidate.
