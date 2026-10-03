# Pilot 002 request and response boundaries

Offline only. No new provider call, credential read, signing operation, claim,
candidate execution, Lambda deployment or state transition is included.

Exact-request signature verification is prepared separately in
`docs/pilot-002-signed-allowances.md`; no real allowance has been issued.

The approved attempt ledger is now deployed and verified. Each of its three
fixed role keys is absent; no budget is reserved. Existing provider settings and
permissions are unchanged except for the three approved exact-row policies.
Both Factory task states remain unchanged. Evidence:
`factory/evidence/pilot-002-attempt-ledger-live-proof-2026-10-03.json`.

## Exact source and role separation

`factory/evidence/pilot-002-baseline-source.json` contains only the two approved
files retrieved from the private acceptance repository at
`1c876ac42305fb9295424759424a74263e4fc330`. Git blob hashes were checked against
GitHub's content responses. The complete baseline snapshot, task contract and
task/budget approval have pinned SHA-256 hashes. The baseline code was not run.

`pilot002_packets.builder_packet` constructs deterministic OpenAI Builder task
material. A response must echo the task and packet digest and contain complete
UTF-8 text for exactly `fingerprint.py` and `tests/test_fingerprint.py`. Unknown
paths, duplicate JSON fields, malformed UTF-8, empty or oversized files, extra
fields and different task bindings are rejected without writing or executing code.

`review_packet` parses that Builder response and binds the exact candidate text
and supplied commit to separate Anthropic Inspector and Google QA packets.
Reviewer focus differs, but both receive the same full acceptance criteria and
candidate. A response for one role, candidate or packet cannot satisfy another.
High or critical findings cannot carry ACCEPTED. The parsers preserve explicit
untrusted-result labels and never assert that tests ran or that a gate passed.

Every packet/response is bounded to 32 KiB; individual candidate files to 16 KiB
and combined candidate content to 24 KiB. These byte bounds are not provider
token counts or a cost quote. Future provider wrappers must count/bound the full
serialized request, including their own instructions and response schema.

## Remaining activation work

These hashes establish byte consistency, not model authorship or authorization.
The supplied candidate commit is explicitly unverified. The future publisher
must bind it to the actual repository tree before any live review authorization.
Provider-specific payloads, complete output schemas, signed time-limited owner
allowances, fresh pricing and readiness, durable claim integration, constrained
candidate testing and independent signed gate evidence remain required.

No new live handler consumes these packets yet. Existing fixed-candidate model
entrypoints must not be repurposed by changing only a task ID. Preserve consumed
historical ledgers and one-call approvals; do not interpret a parsed assessment
as dispatch, merge or production permission.
