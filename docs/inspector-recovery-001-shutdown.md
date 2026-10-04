# Independent recovery concurrency shutdown

The offline template defines a dedicated schedule group, execution role and
disabled-by-default schedule. The role grants only PutFunctionConcurrency on
the exact recovery function. Its trust is limited to Scheduler in the fixed
account and exact schedule group. IAM does not constrain the numeric concurrency
value; the reviewed schedule target and runner validation constrain it to zero.
There is no Lambda invocation, provider, secret or ledger permission.

When separately approved and armed, the schedule starts at a deadline 10 to 30
minutes ahead and repeats every minute for 15 minutes. Every request sets zero;
up to two retries apply only to this idempotent shutdown operation, never to a
model call. The end time bounds the schedule; it is retained for audit. Scheduler
timing is not an exact second-level guarantee. The schedule cannot stop a Lambda
invocation already running, restore the disabled package or remove live IAM
permissions. Those tasks remain the runner's verified rollback and subsequent
operator reconciliation.

The recovery runner requires exact armed schedule configuration before activation
and again before invocation. The deadline is part of the approved preview digest
and cannot exceed the signed allowance window. Other schedules targeting the
recovery function remain forbidden. This change does not deploy or arm anything.

Before live use, obtain approval for the exact AWS resources, verify deployment
and role permissions, and rehearse scheduled execution while the recovery
function remains disabled. Confirm the actual PutFunctionConcurrency event and
resulting zero concurrency; merely reading an enabled schedule is not execution
proof. Prepare fresh schedule times and exact approvals for the live window.

AWS references checked for this design:
- [Universal SDK targets](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html)
- [Schedule-group trust restrictions](https://docs.aws.amazon.com/scheduler/latest/UserGuide/cross-service-confused-deputy-prevention.html)
- [PutFunctionConcurrency](https://docs.aws.amazon.com/lambda/latest/api/API_PutFunctionConcurrency.html)
