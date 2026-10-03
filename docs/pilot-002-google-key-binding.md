# Pilot 002 private Google key comparison

PR #344's approved audit succeeded once for OpenAI and once for Google, both HTTP
200 with the expected model metadata. No generation requests or attempt claims
occurred. The sanitized evidence is in
`factory/evidence/pilot-002-credential-metadata-verified.json`.

The Google console shows `Tims Software Factory QA` in project
`gen-lang-client-0247455615`, number `775833138497`, with resource
`projects/775833138497/locations/global/keys/cb9311fc-42e2-4de4-bf83-80082e6282c1`.
That name alone does not prove the AWS secret contains the same key.

## Proposed execution, requiring owner approval

Authorize the existing signed-in Google Cloud Shell session to use the account's
Google Cloud credentials. Its console dialog states this permits this and future
Google Cloud API calls. This is session authorization, not an IAM role or API key
creation. Then use the reviewed script on each provider's own Cloud Shell:

1. Generate one fresh public 32-byte random nonce, represented as 64 lowercase
   hexadecimal characters. Use the identical nonce for both observations.
2. On Google Cloud Shell, use its existing OAuth identity to GET the exact project,
   exact named key metadata and its key string. Identity checks precede the key
   read. The token goes only to Google's resource-manager and API-keys hosts.
3. On AWS CloudShell, read only Google QA secret version
   `db69f4bf-38c0-43d5-8bbf-ce20d8e07282`, after checking the AWS account.
4. Each side computes a domain-separated SHA-256 fingerprint in memory. Export
   only the fingerprints and public identity fields, never keys or OAuth tokens.
5. Compare the two reports with `compare`, within five minutes. Reject different
   nonces, identities, key fingerprints, stale observations or failed reads.

CLI: `python scripts/check_pilot002_google_binding.py SIDE NONCE OUTPUT
--owner-approved-private-comparison`, with SIDE `aws` or `google` and a fresh
absolute output path outside the checkout. Each exclusive output starts with a
marker before reads. Interrupted work requires reconciliation; no automatic
retry. Direct Google HTTP requests have fixed hosts/paths, verified TLS, bounded
JSON responses, no redirects or retries. OAuth acquisition uses the installed
gcloud CLI with captured output; its ordinary credential refresh may occur.
Exceptions and response bodies are never printed or stored in audit reports.

No raw API key moves between AWS and Google. No model endpoint is called, no
secret is changed, and no execution flag, budget, attempt or task state changes.
All workers remain disabled. A matching comparison establishes only the named
credential's project ownership at that observation time. It does not establish
billing, quota, generation access or a live allowance. Recheck billing before the
short-lived free-tier qualification is signed.

The Google API key metadata and key-string methods are separate operations:
[Google key information documentation](https://docs.cloud.google.com/api-keys/docs/get-info-api-keys).
The script uses the documented `getKeyString` route, not `lookupKey`, so an API
key is never put in a request URL. Tests use synthetic keys and mocked services.
The script is not bundled into the deployed runtime.
