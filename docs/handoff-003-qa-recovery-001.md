# Separate QA recovery preparation

The original handoff003 QA attempt remains consumed and held. No signed QA
result exists, its actual charge is unknown, and the dispatcher correctly stops.
Builder and Inspector results remain usable as verified historical evidence,
not as permission to invoke another model.

The owner's 50-action authorization permits a separate USD0.25 QA scope within
the USD2 additional ceiling. Keeping the original USD0.75 allocation intact,
this scope brings conservative allocated reservations to USD1.00. It has a new
task, attempt table and claim key, exactly one provider call, and no retries.
It does not rerun Builder or Inspector, reset the original QA row, release its
hold, or declare the original three-stage chain completed.

Preparation pins and independently audits the saved signatures, candidate test
evidence, uncertain QA observation and disabled-state observations. It binds the
exact QA request bytes to a new source revision and scope. The proposed worker
allows 240 seconds and the transport 150 seconds; the longer timeout is not a
guarantee of provider availability and does not increase the output-token cap.

`python scripts/prepare_handoff003_qa_recovery.py` performs offline preparation
only. No recovery runtime or allowance is activated by this change. A fresh
owner-signed exact-request allowance, current model/pricing qualification,
isolated permanent claim, scoped deployment, and disabled-state verification
are still required before the single recovery invocation. Review acceptance
does not authorize a task-state transition, merge, schedule or production release.
# Live outcome: stopped after provider HTTP 503

The one fresh recovery invocation on source
`0b460df22c4abc02a038be0f0a8345c1779eb58b` returned provider HTTP 503 on
2026-10-06 at 05:33:58 UTC. The worker restored disabled code and zero
concurrency at 05:34:06 UTC. No retry occurred. Both the original QA claim
and this separate recovery claim remain STARTED with their full $0.25 holds;
neither actual charge is known. All 19 observed components are disabled and
the authoritative Pilot002 task remains PAUSED version 0 with no active leases.

The saved public evidence is under
`factory/evidence/handoff-003-qa-recovery-001-live/`.
`python scripts/verify_handoff003_qa_recovery_evidence.py` validates the
historical owner signature, separate permanent claim, 503 outcome and shutdown.
This audit grants no execution, retry, hold release or gate authority.
