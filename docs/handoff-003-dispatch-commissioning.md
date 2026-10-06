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
