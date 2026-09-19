# Bonus Library production operations

## Authoritative release

- Product repository: `timbrydges/bonus-library`
- Authorized commit: `236eb2fe5bc80f8c3e826bd2e40dea3651e2d0c7`
- Current Vercel deployment: `dpl_GS9tWc8spnisPi64biBi4fgk9fMM`
- Production URL: `https://bonus-library.vercel.app`
- Approved scope: owner-only ZIP ingestion up to 50 MB
- Factory contract: `factory/projects/bonus-library-importer/operating-contract.yaml`
- Authorization evidence: `factory/evidence/bonus-library-release-authorization-2026-09-19.json`

Direct PDF, DOCX, and PPTX inputs, public access, Google Drive synchronization,
bulk import, infrastructure changes, and Factory operational-role activation
remain denied.

## Routine health check

Confirm all of the following before declaring production healthy:

1. Vercel identifies the authorized deployment as READY, Latest, Current, and
   attached to `bonus-library.vercel.app`.
2. The deployed source commit exactly matches the Factory contract.
3. An unauthenticated request to `/` redirects to `/login`, and `/login`
   returns successfully.
4. The recent Vercel log window contains no warning, error, or fatal events.
5. The owner can sign in and render the dashboard without exposing a source
   object or persistent download URL.

The release is unhealthy if any check fails or the deployed commit differs
from the authorized commit. A newer deployment is not automatically an
authorized deployment.

## Incident triggers

Contain and roll back immediately for any of these conditions:

- authentication or authorization bypass;
- public source-object exposure or a non-expiring download URL;
- checksum, provenance, approved-record, or release-binding mismatch;
- retry-created duplicate record, reservation, usage entry, or provider charge;
- unresolved high or critical security finding;
- production commit or deployment drift from the Factory authorization;
- repeated runtime errors that affect upload, approval, or private download.

## Containment and rollback

1. Stop new product merges and provider-triggering verification.
2. Record the current deployment, commit, observed failure, and first known
   failure time without copying secrets, signed URLs, or source content.
3. Point production back to known-good deployment
   `dpl_xEHKsjcnh5G15MKrEnfEy76pHVnh` only under Tim's owner authority.
4. Confirm READY status, the login boundary, signed-in dashboard, private cover,
   and private ZIP download.
5. Inspect the restored deployment's recent runtime logs for warnings, errors,
   and fatal events.
6. Record the rollback result as durable Factory evidence before reopening work.

Rollback changes production traffic and is never an autonomous agent action.

## Change and release protocol

Every product change creates a new commit and therefore needs a new exact-version
authorization. The safe sequence is:

1. Open a product pull request and validate its preview deployment.
2. Run deterministic tests plus the acceptance checks affected by the change.
3. Record the candidate commit and preview deployment in Factory evidence.
4. Obtain Tim's exact-version authorization.
5. Merge the Factory authorization change and require all control-plane checks.
6. Promote only the authorized product artifact to production.
7. Re-run the routine health check and record the result.

Do not treat a green Vercel deployment, a green product pull request, or a merge
to product `main` as release authorization.

## Known control gap and next hardening

Vercel currently deploys product `main` automatically. That can place a newer
commit in production before its exact-version Factory authorization is merged.
Until this is hardened, product merges must be held and coordinated with the
release protocol above.

The recommended hardening is to separate ordinary product integration from the
Vercel production branch, then allow production promotion only after the Factory
has recorded Tim's authorization for the exact candidate commit and deployment.
Changing that deployment behavior requires a separate owner-approved operation.
