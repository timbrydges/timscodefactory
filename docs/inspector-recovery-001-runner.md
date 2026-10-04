# One-shot recovery execution

The dedicated runner requires separately approved digests for the complete
signing plan and execution preview, a signed recovery allowance and the recorded
signing workflow run. It reads fixed committed candidate/preview files, neither
of which is added by this change. The preview binds the exact change set,
immutable package, active template, disabled rollback target and explicit
shared-capacity choice. The signing run number is recorded for audit; the
cryptographic authority comes from verifying the enrolled owner signature.

Before mutation it verifies account, signed scope and expiry, exact CloudFormation
preview, code bytes, disabled function, role trust and permissions, absent
recovery attempt, unchanged original worker code/disabled controls, original
consumed Inspector hold, unused QA, shared capacity and absence of invocation
surfaces or schedules. All SDK clients use one request attempt. The runner never
signs, modifies attempt records directly, or retries a model invocation.

Exclusive flushed execution and invocation markers precede their respective
operations. After activation it rechecks runtime code/configuration/permissions,
signature and attempt state, then submits one synchronous invocation. Results
are bounded and retained as untrusted evidence. A captured failed review is a
stop, not an accepted review or successful exit. No result grants release or
gate authority. Acceptance and ledger/cost reconciliation are separate work.

The finally block immediately forces concurrency zero, waits for an uncertain
stack operation to settle, applies zero again, and restores the exact disabled
template, removing the temporary recovery access policy. It verifies code,
configuration, permissions, stable stack status, original workers and unchanged
original attempt records. Shutdown errors are recorded without retrying the
invocation. An unverified shutdown produces a failing exit status and needs
operator reconciliation; it must not be reported as complete.

Loss of the operator process or CloudShell can prevent its finally block from
running. The runner therefore also requires the exact independent concurrency
shutdown schedule to be armed, checks it before activation and invocation, and
binds its deadline in the approved preview. Schedule configuration alone does
not prove successful execution; a separate AWS rehearsal remains required.
The schedule stops new executions but does not restore code or remove temporary
permissions, so operator reconciliation remains necessary after process loss.
No signing or live invocation is authorized by merging this source. The
additional recovery call remains capped at USD 0.25, and the original Inspector
attempt remains permanently consumed.
