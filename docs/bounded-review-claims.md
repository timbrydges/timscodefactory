# Fresh provider claim storage

`infra/review/provider-claims-stack.json` defines the separate
`tims-factory-bounded-review-001-attempts` table used by `ReviewProviderClaims`.
It has one string partition key, `PK`, and on-demand billing. It creates no IAM
grants, workers, schedules or provider reservations.

The three application keys are `BOUNDED_REVIEW#001#ROLE#builder`,
`BOUNDED_REVIEW#001#ROLE#inspector`, and `BOUNDED_REVIEW#001#ROLE#qa`.
Conditional writes permanently advance each record from RESERVED to STARTED to
COMPLETE. An uncertain send remains consumed. Expiration closes authorization;
it never frees a claim or refunds its reserved budget.

Deletion protection is enabled. CloudFormation deletion and replacement both
retain the table. TTL is deliberately absent, including on `expires_at`.
Do not delete, replace, reset, or enable TTL on this table to retry a provider.
Do not insert synthetic canary claims into these three real-run keys.

Creation requires the approved exact template, account 666730517561 and region
ca-central-1. Reconcile an existing stack or table before any creation attempt;
never overwrite it. Verify stack completion, exact template, PK schema,
on-demand billing, deletion protection, disabled TTL, and consistent reads of
the three expected keys. An empty table proves only storage readiness, not
permission to spend or evidence of successful review.

Persistent storage and requests are metered. Tim explicitly approved this
bounded storage setup on 2026-10-06. It does not increase the USD2.75 aggregate
provider ceiling or consume the unused USD0.75 next-run reservation.
