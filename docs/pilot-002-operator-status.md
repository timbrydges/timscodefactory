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
