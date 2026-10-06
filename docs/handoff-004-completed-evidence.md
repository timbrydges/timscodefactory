# Completed bounded controller handoff 004

On 2026-10-06, source `1b2819985098e63acf1d29ad2c31fca46a0a9231`
completed one controller-dispatched call per provider against acceptance candidate
`994719a384b7ac96abeb67e4b2addcab2deb4763`.

| Role | Model | Signed result | Reported USD |
| --- | --- | --- | ---: |
| Builder | OpenAI gpt-5.6-sol | Valid candidate | 0.084416 |
| Inspector | Bedrock Sonnet 4.5 | ACCEPTED | 0.021354 |
| QA | Google gemini-3.7-flash | ACCEPTED | 0.005178 |

All three linked role signatures verified. The exact candidate passed 17 Linux
Python 3.12 tests, with no skipped tests or credentials in the test environment.
The candidate files match the pinned acceptance baseline. This proves the bounded
handoff and review path; it does not demonstrate new feature implementation.

Owner signing runs were `37422758219`, `37423230789`, and `37423547292`.
Each provider and controller claim is permanently COMPLETE, with its USD0.25
reservation still HELD. Nothing was reset or retried. Reported total is
USD0.110948, not an invoice reconciliation.

The read-only controller invocation returned `COMPLETED_NO_DISPATCH` with zero
worker invocations after worker invocation permissions were removed. Final
observations found all 24 tracked functions disabled, all prior attempts unchanged,
and the authoritative Pilot 002 task still PAUSED at version 0 with no leases.
The two earlier uncertain QA holds remain unreconciled and non-reusable.

`factory/evidence/handoff-004-live` contains the signed envelopes, permanent
claim observations, independent test proof, historical verification report,
controller completion result, invocation/restoration journals, package identities,
and before/after observations. Run
`python scripts/verify_handoff004_saved_evidence.py` to audit them. Signatures
are checked at the saved verification time; saved database, test, and shutdown
observations are operator evidence rather than cryptographic attestations.

This archive grants no execution, scheduling, task-transition, gate, or production
release authority. The fixed read-only status inventory now covers 24 components
and 21 provider-attempt locations. The batch's conservative USD2 allocation is
fully reserved; further paid scopes require a new budget rather than reusing holds.
