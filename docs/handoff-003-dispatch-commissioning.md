# Dispatcher commissioning

Handoff003 is a fresh bounded task within the owner's 2026-10-05 authorization
for 50 actions and at most USD2 of additional cost. Allocate at most USD0.75:
one OpenAI Builder, one Anthropic Inspector and one Google QA attempt, each
with a permanent USD0.25 reservation and no retries. Existing handoff001/002
claims, holds, receipts and source bindings are unchanged and cannot be reused.

The new runtime namespace preserves prior executable evidence. It reuses the
existing fixed provider credential and signer routes, but has separate worker
names, attempt table, controller claims, task and signed allowance kinds.
Its signing workflow excludes every other signing job when selected.

The dispatcher is disabled by default. A reviewed package contains one signed
role activation, one exact immutable worker version and package hash, and a
source-bound configuration digest. The dispatcher has no credential, provider
or signing permission. Its foundation has no worker invocation permission;
each enabled commissioning stage needs a separately pinned numeric version.
Reads cannot substitute errors for absent rows. Claims are permanent, SDK
retries are disabled, and uncertain outcomes stop. Completed signed evidence
can be recovered without another worker invocation.

QA dispatch additionally requires packaged independent Linux Python3.12 test
evidence for the exact unchanged baseline candidate before any AWS call. This
commissioning scope does not authorize execution of arbitrary generated code.
All receipt signatures and source/request/candidate bindings remain mandatory.

Commissioning proceeds by preparing and signing each predecessor-bound stage,
publishing its worker and dispatcher versions, invoking the dispatcher once,
and restoring zero concurrency and disabled foundations. This proves delegated
dispatch, not unattended creation of new tasks or owner allowances. No schedule,
automatic merge, release authority or authoritative task-state transition is
introduced by this preparation.

## Recorded commissioning result

Source `059f42ae087b0c6429e71e0cb5e0a24f978eed88` completed one Builder and
one Inspector invocation with authenticated signed results. The exact candidate
passed all 17 independent Linux Python 3.12 tests. Reported completed cost is
USD0.101892. QA made its single invocation but stopped at the provider boundary
after about 91 seconds; the old transport did not retain an exact error category.
This timing is consistent with its 90-second timeout, not proof of the cause.
QA's actual charge is unknown and its USD0.25 hold remains permanent.

The account quota was 11 concurrent executions with a minimum unreserved pool
of 10. Reserving one slot for both dispatcher and worker was rejected before
any invocation. After proving both claims absent, commissioning used one reserved
worker slot and the shared pool for the dispatcher. Immutable versions, signed
caps and conditional permanent claims still bound execution. Both functions
were restored to zero concurrency and dispatcher invoke rights were removed.

A subsequent read-only dispatcher invocation, with all workers disabled and no
worker-invocation rights, returned `STOPPED_NO_RETRY` without changing provider
attempts. This run is not a completed three-model chain and cannot be retried.
The saved audit separates signed results from unsigned operator observations:
`python scripts/verify_handoff003_saved_evidence.py`.

Future source builds retain only timeout, numeric HTTP status, or unknown failure
categories. The dispatcher records these as terminal failures without retaining
provider error text, creating a success receipt, releasing a hold, or retrying.
This change cannot recover the missing diagnostic category of the recorded run.
