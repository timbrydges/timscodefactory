# Interrupted-session shutdown

An operator process can disappear before its `finally` cleanup executes. Run
`python scripts/quiesce_handoff004.py NEW_REPORT.jsonl` from the reviewed
repository with existing AWS operator credentials to block new handoff004
invocations. Use a new report path for each reconciliation attempt.

The command targets only the three handoff004 workers and its dispatcher in
account 666730517561, ca-central-1. It sets each reserved concurrency to zero,
then removes the dispatcher worker-invocation grant only when the existing
policy exactly matches the reviewed policy shape. An unexpected policy is
reported and not replaced. Every stop is attempted independently, including
when an earlier stop or journal write fails. SDK retries are disabled.

This is repeatable shutdown, not a provider retry. It does not invoke workers,
change code or environment variables, access provider secrets, change schedules,
or write attempt/budget tables. Already-running Lambda executions are not
cancelled. Reconcile their permanent records separately; neither this command
nor a zero-concurrency observation authorizes another attempt.

Exit zero means all four zero-concurrency readbacks and the narrow dispatcher
policy were observed successfully, with no operation or journal errors. Any
failure returns exit two and `SHUTDOWN_INCOMPLETE`. Saved observations are not
an atomic snapshot and do not establish that prior calls were uncharged.
