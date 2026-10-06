# Synthetic review persistence canary

`scripts/review_progression_canary.py` verifies the bound Inspector and QA
validators with real signatures and DynamoDB persistence. It uses only the fixed
`review-inspector-canary-001` and `review-qa-canary-001` task partitions plus
their same-named synthetic scope objectives in `tims-software-factory-state`.

The command requires `--execute`, the exact source commit and unused journal and
result paths. It refuses existing task records, creates its exclusive journal
before any mutation, and uses AWS SDK clients with retries disabled in account
666730517561, ca-central-1. State and lease fixtures are created atomically.

Each case verifies that missing independent test acceptance leaves state
unchanged, then persists exactly one signed transition, revokes its lease and
checks that repeating the consumed receipt cannot advance again. Rows remain
for audit. An interrupted run must be reconciled by reading those rows, never
reset or repeated. No schedule, worker, production task, budget or provider is
activated.

All signers, verdicts and test-output bytes in this canary are synthetic. Passing
proves validation and persistence mechanics, not independent model review,
actual candidate tests, production trust or autonomous delivery. The optional
Moto integration test exercises both roles and refuses a second run; the live
AWS result is a separate evidence requirement.
