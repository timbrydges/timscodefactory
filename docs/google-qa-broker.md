# Disabled Google QA broker deployment proposal

## Verified deployment, 2026-10-02

The original five-resource deployment rolled back because the account's applied
concurrency limit is 10 and AWS requires 10 unreserved slots. The protected
attempt table was retained. After separate owner approval, recovery stack
`tims-factory-google-qa-broker-recovery` created the role, logs, function and
immutable version 1 using shared capacity and the retained external table.
There is no per-function reserved-concurrency cap in this approved recovery.

Version 1 uses source `8e61da3fefb0c0805efb10bda2c6bddc6cd63ffa` and code hash
`/+Hw3F5r40GB2vZhjPuAVK8uQ+fi7qyutO/Hjmf38Es=`. Exact permissions and configuration
were verified. One synchronous probe passed, with no retries, model calls,
credential reads or state writes; the attempt key remained absent afterwards.
Evidence: `factory/evidence/google-qa-broker-live-proof-2026-10-02.json`.
The original proposal below records the superseded reserved-capacity design;
do not execute it against the retained table or the deployed function.
The recovery does not depend on pending AWS Support case 179098392900384.

Next preparation and disclosure boundary: `docs/google-qa-preflight.md`.

## Original proposal (superseded by approved recovery)

The next cloud change requires owner approval because it creates an AWS role
that can read the dedicated Google QA secret. It does not authorize a model
call, spend reservation, signed verdict or task transition.

Five Add resources are proposed in stack `tims-factory-google-qa-broker`:

- `tims-factory-google-qa-attempts`: on-demand DynamoDB, retained, deletion
  protection enabled, encrypted, no TTL. It is separate from existing budgets
  and Factory state. The role has PutItem/GetItem/UpdateItem only for partition
  `GOOGLE_QA#google-qa-pilot-001`; no DeleteItem, scans or other table grants.
- `/aws/lambda/tims-factory-google-qa-broker`: 14-day logs.
- `tims-factory-google-qa-broker`: Lambda execution role, limited to its own logs,
  the exact Google QA secret's AWSCURRENT stage, and the above ledger partition.
  No OpenAI secret, signing keys, Bedrock, Factory task tables or invocation grants.
- Broker Lambda: Python 3.12, 128 MiB, 120 seconds, reserved concurrency 1,
  `FACTORY_GOOGLE_QA_ENABLED=false`, pinned secret ARN and verified version ID.
- Immutable Lambda version bound to the clean package's CodeSha256.

The handler has no generation branch: it only accepts a source-bound disabled
boundary probe, returns zero secret reads/writes/model calls, and rejects even
that probe if the enable flag changes. No new events, public URLs, scheduled
triggers or QA/controller invocation grants are proposed. Existing role versions,
budgets, task state, signing registries and schedule are outside this change.

After an approved deployment, verify exact resources, role policy and package
hash, then invoke the immutable boundary version once with no retries. The probe
does not read the credential, contact Google or create a ledger item. Unknown
invocation outcomes require inspection, not another probe.

## At-most-once primitive

`GoogleQaAttemptStore.begin` conditionally writes a single fixed key containing
request, approval and source digests. A new process, new request, code revision,
existing COMPLETE row or uncertain write cannot acquire another attempt. Any
write exception fails closed without reading and retrying. Completion uses a
conditional update requiring STARTED plus the exact request digest. No path
deletes a claim, refunds it, resets status or relies on TTL expiry.

This primitive stores a binding to a separately validated approval; a digest
alone is not proof of authorization. It does not reserve money, and is not yet
called by a live handler. The future pilot still needs owner-approved fresh
scope/pricing, durable budget reservation, exact token accounting, broker-only
credential loading, Google provider qualification and independent signed QA
evidence before any gate can advance. Do not wire the transport directly to an
event or treat the existing local transport latch as durable protection.

## Build and review

`scripts/prepare_google_qa_broker.py OUT.json` renders the template offline.
`scripts/build_google_qa_broker_package.py OUT.zip` uses the existing clean-source,
hash-locked Linux wheel builder and includes only the pinned review evidence
needed by the prepared Google request. Build outside the checkout. Upload to an
immutable version in the existing artifact bucket and bind that version plus
CodeSha256 in a CREATE change set. Confirm exactly five Add actions and stop
before executing it until the owner approves these permissions.

This adds metered DynamoDB, Lambda, logging and artifact storage usage. It creates
no additional API secret or customer-managed KMS key; previously approved secret
storage and identity-key charges continue. It neither links Google billing nor
authorizes paid inference.
