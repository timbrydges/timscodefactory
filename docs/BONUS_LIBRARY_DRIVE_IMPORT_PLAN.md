# Bonus Library Phase 2: Google Drive import plan

Architecture status: owner-approved bounded baseline on 2026-09-19. Google
Cloud, Drive, Supabase, implementation, scheduling, and release actions remain
denied until their individual gates are authorized and verified.

## Recommended first slice

Add an owner-triggered, one-way scan of one private Google Drive folder. Import
only direct ZIP children, at most 10 files and 250 MB per run. Each file must
pass the existing 50 MB ZIP validation boundary before it is copied into the
private, immutable Supabase source bucket and finalized as an unpublished draft.

The import must not generate content, approve, publish, replace, delete, or
create a public link. Tim keeps the existing review and approval path.

## Identity design

Use Vercel OIDC to exchange a deployment-bound assertion for short-lived Google
credentials that impersonate a dedicated service account. Share only the source
folder with that account as Viewer. Do not create a service-account JSON key,
store an OAuth refresh token, enable domain-wide delegation, or use a public
folder.

Google Drive API v3 lists direct folder children with a parent query and pages
through every result. Eligible blob files are downloaded with `files.get` and
`alt=media`. The importer requests only the fields needed to bind file ID,
version, name, MIME type, size, checksum when available, modified time, parents,
and page token.

References:

- https://developers.google.com/workspace/drive/api/guides/search-files
- https://developers.google.com/workspace/drive/api/guides/manage-downloads
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth
- https://vercel.com/docs/oidc/gcp
- https://vercel.com/docs/cron-jobs/manage-cron-jobs

## Delivery sequence

1. Approve the architecture and threat model.
2. Configure a dedicated Google project, Drive API, workload identity pool,
   deployment-bound provider, and read-only service account.
3. Share one exact private folder with the service account and verify that a
   canary cannot list any other Drive content.
4. Add private provenance and import-run records with RLS and additive,
   backward-compatible migration controls.
5. Implement and test the owner-triggered importer against Drive fixtures, then
   one disposable live ZIP.
6. Independently inspect the exact candidate and obtain exact-version release
   authorization.
7. After manual import is stable, separately authorize and add the authenticated
   scheduled scan using the same bounded service.

Production remains on the currently authorized ZIP-only version throughout
planning and implementation. A green preview, Drive canary, or schema test is
not production authorization.
