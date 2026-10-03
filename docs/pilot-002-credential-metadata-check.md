# Pilot 002 private credential metadata check

The next proposed audit reads the two existing provider credentials only inside
AWS CloudShell memory, then sends each credential exclusively to its own provider
in an HTTPS authentication header. No credential is put in a URL, command line,
repository, report or chat. The reviewed immutable versions are:

- Builder: OpenAI acceptance secret, version ebb6cc21-2df9-4b06-8f55-2b0661f27f69.
- QA: Google QA secret, version db69f4bf-38c0-43d5-8bbf-ce20d8e07282.

The destinations and methods are fixed:

- GET `https://api.openai.com/v1/models/gpt-5.6-sol` using Authorization: Bearer.
- GET `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash`
  using x-goog-api-key.

These are the documented model metadata methods from
[OpenAI](https://developers.openai.com/api/reference/resources/models/methods/retrieve)
and [Google](https://ai.google.dev/api/models). They do not send prompts or request
generated content. The script performs at most one HTTPS request per provider,
without redirects, retries or environment proxy discovery. Response bodies are
bounded and never copied into reports. Only fixed role/model identifiers, status,
HTTP code, credential-format label and request counts are recorded. Secret reads
require the exact ARN and VersionId; unrecognized credential JSON fails closed.

The CLI requires `--execute-owner-approved-metadata-checks` and an exclusive new
output outside the repository. It writes a started marker before reads. An
interrupted or failed audit must be reconciled before any explicitly approved new
audit; the tool never retries automatically. SDK debug dumps are suppressed while
AWS service audit logging remains unchanged. Tests use synthetic credentials and
fake provider connections only. This script is not packaged into Lambda.

## Approval and limits

The owner must approve the exact credential reads and transmission to OpenAI and
Google before this script is run. PR #343's permission-deployment approval excluded
these reads. Preparing and testing this script does not perform them.

A successful authenticated metadata response proves only that the endpoint
accepted that credential and returned the expected model metadata. It does not
prove generation permission, available quota/credit, request compatibility, cost
bounds, or Google project ownership/billing. Google's separate
[key-to-project lookup](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey)
requires Google OAuth permission and is not included in this audit. No owner
allowance, attempt claim, model budget, task state or activation flag is changed.
All role functions remain disabled at concurrency zero.
