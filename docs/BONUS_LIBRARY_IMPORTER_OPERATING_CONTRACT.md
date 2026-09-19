# Bonus Library importer — Project #2 operating contract

## Decision state

Tim authorized the exact ZIP-only release on 2026-09-19 after all acceptance and
rollback gates passed. The authorization is bound to Bonus Library commit
`236eb2fe5bc80f8c3e826bd2e40dea3651e2d0c7` and current READY production deployment
`dpl_GS9tWc8spnisPi64biBi4fgk9fMM`. Bounded live provider calls and release are
allowed. Infrastructure changes and Factory operational-role activation remain denied.

## Bounded first slice

Project #2 will prove one complete, private ingestion path:

1. Tim authenticates and uploads one ZIP package up to 50 MB.
2. The source is stored privately with an immutable identifier and checksum.
3. The system extracts bounded metadata and treats every source value as
   untrusted data.
4. Approved providers draft missing title, description, or cover artwork under
   the Factory's cumulative budget and usage ledger.
5. The item remains unpublished until Tim approves it.
6. An approved item receives a download link that expires within five minutes.

Direct PDF, DOCX, and PPTX inputs remain deferred. Google Drive sync, folder
watching, bulk import, public users, payments, analytics, notifications,
arbitrary URL crawling, and source deletion are not part of this slice.

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

The exact-version authorization is recorded in
`factory/evidence/bonus-library-release-authorization-2026-09-19.json`; acceptance
and rollback closeout is recorded in
`factory/evidence/bonus-library-acceptance-closeout-2026-09-19.json`.

The machine-readable authority is
`factory/projects/bonus-library-importer/operating-contract.yaml`; validation is
defined by `factory/schemas/project-operating-contract.schema.json`.
