# Bonus Library Importer — Architecture Dry Run

Status: `NON_AUTHORITATIVE_DRY_RUN_COMPLETE`  
Authority: owner-approved design baseline; operational activation remains denied
Bound contract: `bonus-library-importer-001`

This is a design and threat-model rehearsal for the approved dry-run-only contract. It created no project repository, infrastructure, identity, provider call, implementation, or release. The machine-readable source is `factory/projects/bonus-library-importer/planner-dry-run.yaml`.

## Proposed boundary

The single-item path is owner UI → authentication → streaming quarantine → fail-closed validation → private immutable storage → unpublished metadata draft → budget-controlled generation of missing fields → Tim-only approval → checksum-bound publication → owner-scoped download link expiring within five minutes.

No AI or agent can approve or publish. Source bytes and filenames are untrusted data. The system never executes archive contents, never exposes a storage listing, and never modifies an approved source.

## Principal components

| Component | Responsibility |
|---|---|
| Owner web UI and authentication boundary | Permit only Tim to upload, review, approve, publish, and download |
| Ingestion API and quarantine validator | Stream, size-limit, checksum, identify, and safely inspect one supported package |
| Private object storage and metadata store | Keep source and generated assets private, immutable, versioned, and auditable |
| Provider budget broker | Atomically reserve spend/dispatches and persist reconciled provider usage |
| Draft review service | Keep generated content unpublished and bind Tim's decision to exact checksums |
| Signed-download service | Issue a single-object, owner-authorized link for no more than five minutes |
| Append-only audit log | Preserve actors, transitions, evidence digests, and rollback history |

## Fail-closed threats

The design explicitly covers authentication bypass, path traversal, links and special archive entries, executables, archive bombs, type spoofing, prompt injection, provider data exfiltration, public object exposure, retry/replay charges, checksum substitution, signed-link leakage, budget overflow, and Inspector/release evidence substitution.

Each threat has a deterministic failure mode in the machine-readable artifact. Security failures reject intake, deny dispatch/publication/link issuance, or trigger rollback; they never fall through to a permissive state.

## Evidence and rollback

All ten acceptance criteria (`BL-01` through `BL-10`) map to named components and required evidence. Rollback restores the prior exact application artifact and published metadata revision while retaining immutable source objects, approvals, and audit events. Provider dispatch and download-link issuance can be disabled independently.

## Decisions intentionally left open

The web runtime, owner authentication provider, relational/object-storage services, text/image generation providers, and concrete archive expansion limits remain unbound. Selecting vendors during a non-authoritative rehearsal would create accidental implementation authority.

## Owner approval

Tim approved the architecture and threat model on 2026-09-17. The approval accepts this bounded design baseline only. It does not authorize repository creation, infrastructure, identities, provider calls, implementation, merge, or release; those remain denied until their own gates pass.
