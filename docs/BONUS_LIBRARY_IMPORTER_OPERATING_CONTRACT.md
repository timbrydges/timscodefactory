# Bonus Library importer — Project #2 operating contract

## Decision state

Tim approved this contract for dry-run architecture work on 2026-09-17.
Contract validation and architecture dry runs are allowed. Repository creation,
infrastructure, provider calls, implementation, and release remain denied.

## Bounded first slice

Project #2 will prove one complete, private ingestion path:

1. Tim authenticates and uploads one supported package up to 50 MB.
2. The source is stored privately with an immutable identifier and checksum.
3. The system extracts bounded metadata and treats every source value as
   untrusted data.
4. Approved providers draft missing title, description, or cover artwork under
   the Factory's cumulative budget and usage ledger.
5. The item remains unpublished until Tim approves it.
6. An approved item receives a download link that expires within five minutes.

Google Drive sync, folder watching, bulk import, public users, payments,
analytics, notifications, arbitrary URL crawling, and source deletion are not
part of this slice.

## Non-negotiable controls

- The project repository and source storage are private.
- Tim is the only approval and release authority.
- Planner, Builder, and Inspector remain separate identities.
- Exact-commit Inspector evidence and deterministic CI are required.
- Provider exposure is reserved atomically before calls; the hard stop is USD
  10 with no more than three provider dispatches.
- Identical retries are idempotent; conflicting retries fail closed.
- Uploaded content cannot become governing instructions.
- A source object cannot be exposed through a public or non-expiring URL.

The machine-readable authority is
`factory/projects/bonus-library-importer/operating-contract.yaml`; validation is
defined by `factory/schemas/project-operating-contract.schema.json`.
