# Pilot 002 Builder input-token preflight

PR #345's approved private comparison verified that AWS secret version
`db69f4bf-38c0-43d5-8bbf-ce20d8e07282` contains the exact Factory QA key in Google
project `gen-lang-client-0247455615`. The sanitized proof records both independent
observations and their successful comparison. Neither key nor OAuth token was
exported. No model generation occurred.

The next missing Builder measurement is the complete input-token count. The
prepared public request is in `factory/evidence/pilot-002-builder-token-preview.json`:

- Endpoint: POST `https://api.openai.com/v1/responses/input_tokens`.
- Model: `gpt-5.6-sol`; body size: 11,741 canonical UTF-8 bytes.
- Count request: `sha256:38c472c1a4ad1f13af352ef96b1c77f8ba2bc14ede8c081a9d9b10b4cd1622ad`.
- Corresponding generation request: `sha256:80405ec2824f493789ce16329b51c5c275ebf3a473b4fe88cf331a5a3436c81c`.

The [OpenAI input-token endpoint](https://developers.openai.com/api/reference/python/resources/responses/subresources/input_tokens/methods/count)
returns a token count. The prepared body preserves the generation request's model,
instructions, full synthetic task and baseline input, empty tools, reasoning,
text format and disabled truncation. Fixed generation-only controls are excluded
from the count endpoint. A changed field or unexpected additional field rejects
preparation, rather than silently omitting new context.

## Exact next approval

After reviewing and merging this preparation, authorize one read of the existing
OpenAI acceptance secret version `ebb6cc21-2df9-4b06-8f55-2b0661f27f69` privately
inside AWS CloudShell. Send it only as an HTTPS authentication header to OpenAI's
fixed token-count endpoint, along with the exact public synthetic request above.
No model generation, Lambda invocation, allowance signing, attempt claim,
activation or retry is included. This is a measurement, not permission to spend
the live role allocation. Do not assume that a successful count proves generation
access or pricing qualification.

The CLI defaults to offline preparation. Execution requires
`--owner-approved-token-count`, `--expected-digest` with the exact count digest,
and `--output` pointing to a fresh file outside a clean checkout. An exclusive
marker is written before credentials or network calls. The report records only
request hashes, source commit, time, status and validated token count. Failure
details and provider response bodies are not echoed. HTTPS verifies certificates,
does not follow redirects and makes one request with no retries. Interrupted
work must be reconciled before any newly authorized attempt.

The measurement does not automatically produce a cost qualification. Before
Builder activation, review current prices, the combined output/reasoning limit,
the count-to-generation mapping, repository binding, owner enrollment and the
exact signed allowance. Inspector and QA requests depend on the real Builder
candidate; do not use fabricated candidate data to qualify those live requests.
All three deployed workers remain disabled. Tests use fake credentials and
connections only. This diagnostic is not included in Lambda packages.
