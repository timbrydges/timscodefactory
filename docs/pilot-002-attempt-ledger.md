# Pilot 002 isolated spending and attempt records

Pending owner approval; offline implementation only. No live handler imports
the new store, no claim is made and no provider request is sent.

The new task was initialized once through controller version 40 and is PAUSED
version 0. Its temporary bootstrap policy was removed, concurrency restored
to zero, and the previous task preserved. See
`factory/evidence/pilot-002-bootstrap-live-proof-2026-10-03.json`.

## Concrete next deployment

Create stack `tims-factory-pilot-002-attempts` with exactly four Add resources:

- One encrypted, on-demand DynamoDB table of the same name. Retain it on stack
  deletion/replacement, enable deletion protection, and configure no TTL.
- Three inline IAM policies, one per existing provider role. Each grants only
  GetItem, PutItem and UpdateItem on its own fixed primary key in this new table.
  Builder: `tims-factory-acceptance-broker-canary`; Inspector:
  `tims-factory-executor-inspector`; Google QA: `tims-factory-google-qa-broker`.

No function, code package, alias, version, environment, secret, signing key,
schedule, Factory state table or historical budget is modified. The policies
add no credential or model access, table scans, deletion or cross-role rows.
The new exact-row grants persist until removed; they do not activate execution.
This proposal adds metered DynamoDB storage/request usage, outside the separate
USD 0.75 provider-generation cap. It requests no provisioned capacity or new KMS key.

Approval is required because the three existing roles gain access to new budget
records. Review the exact CREATE change set and compare its template with
`scripts/prepare_pilot002_attempts.py` before executing. Verify all existing
provider configurations and role policy baselines remain unchanged except for
these three additions, and all three new keys remain absent. Do not invoke any
Lambda or write a test claim to the permanent live ledger.

## At-most-once primitive

The table has only a partition key. The three role keys are fixed to Pilot 002,
its exact task and role; callers cannot choose a new attempt ID or sort key.
Each conditional PutItem simultaneously claims one attempt and holds the full
USD 0.25 ceiling. Three successful claims can hold at most USD 0.75. Different
requests, source versions or approvals cannot reuse a consumed role key.
Concurrency and uncertain writes never cause automatic retries or deletion.

Completion is conditional on STARTED, the same request digest and the full
hold. It records the response digest and observed cost without refunding or
resetting the hold. An over-cap or uncertain result stops with the hold retained.
This primitive is not an authorization verifier or a provider cost estimator.
The future authenticated broker must validate exact request bounds, fresh pricing,
provider readiness and owner authorization before claiming. Caller-supplied
approval digests alone grant nothing. No current handler is wired to this store.

## Remaining live-run gates

Candidate-bound requests for the new task, all three qualified provider routes,
fresh price/input/output bounds, authenticated time-limited authorization and
reviewed runtime access are still required. Google billing/data-use qualification
must be refreshed. Preserve all earlier one-call ledgers. Model results remain
untrusted; do not execute outside private disposable fixtures or advance a
Factory gate without independent bound evidence. No merge or release is granted.
