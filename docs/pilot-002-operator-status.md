# Read-only Pilot 002 operator status

Run `python scripts/observe_pilot002_status.py NEW_REPORT.json` from a reviewed
checkout in the existing authenticated AWS operator environment. It fixes the
account and region, uses one SDK attempt per read, and creates a new report
without overwriting a previous observation. It grants no IAM access.

The report covers seven Pilot 002 workers and seven fixed attempt rows, plus
the authoritative task state. A worker is observed disabled only when its exact
ARN matches, its execution flag is false and reserved concurrency is zero.
Missing fields and failed reads appear as UNKNOWN, never as a successful check.
An absent attempt does not grant permission to call a provider.

Reserved amounts are holds, not bills. The report labels known reported costs
separately and never infers invoice totals from incomplete attempts. Unknown
attempt reads make the reservation total incomplete. All existing consumed
attempts and reservations remain unchanged.

Environment values other than the fixed enable flag, raw attempt payloads,
credentials, and exception messages are omitted from the report. No provider
call, Lambda invocation, write, retry, signing or scheduler API is used.

This closes the initial read-only operator observation gap for the completed
pilot, not the full operator-control milestone. It is not an atomic snapshot,
does not inspect all Factory infrastructure or IAM permissions, and cannot
authorize execution or attest that an entire AWS account is safe. Future
pause/resume controls and autonomous dispatch still need their own tested,
source-bound implementation and live verification.

## Verified observation and offline page

The command from merged source `de0ea9e1f9072079e75e5cf19c1668ee0dd3280f`
was run against the existing AWS operator session at
`2026-10-06T01:01:38Z` (October 5 in Alberta). The redacted report is
`factory/evidence/pilot-002-operator-status-2026-10-05.json`.
All seven workers were observed disabled. Seven consumed attempts retain
USD 1.75 in total reservations; the only recorded completed-attempt cost is
USD 0.087664. This does not represent total actual provider billing.
The task remains PAUSED version 0 with zero active leases. The merged candidate
and offline reviewer assessments did not advance the controller state.

Render any saved report with
`python scripts/render_pilot002_status.py REPORT.json NEW_PAGE.html`.
The standalone page requires no server or external assets, escapes report text,
blocks scripts and network resources through its content policy, and exposes
no mutation controls. It prominently labels the report as a historical snapshot.
