# Bounded failed-review evidence

Inspector's October 4 attempt reached Sonnet, but no accepted review survived.
PR #357 preserves the safe failure stage; this change additionally preserves
bounded reviewer response bytes when validation or completion recording fails.
It cannot recover the old response or reopen the consumed Inspector attempt.

Only Inspector and QA qualify. The workflow must first verify the allowance,
claim its permanent attempt, and obtain response bytes from the one-shot
transport. The existing transport accepts only HTTP 200, JSON content type,
identity encoding and a bounded body. Responses above 262,144 bytes, HTTP error
bodies, exception messages, credentials, request headers and failed transport
operations are excluded from capture. Builder behavior remains unchanged.

If later processing fails, the entry point returns
`PILOT002_REVIEW_FAILED_NO_RETRY` with stage `response` or `completion`, the
response byte count, SHA-256, and base64 body. It explicitly marks the response
untrusted, the review unaccepted, the attempt non-reusable and the reservation
HELD. It conveys no cost, gate, release or completion authority. No extra ledger
write occurs. Completion uncertainty must still be reconciled read-only.

The runner saves the failure envelope before shutdown and reports
STOPPED_NO_RETRY rather than success. Its outer result limit is 524,288 bytes to
accommodate base64 expansion; the provider response and request bounds do not
increase. The envelope is returned to the invoking operator, not printed to
CloudWatch or transmitted to another service. Decode only for offline inspection;
never execute generated text or treat its instructions as authorization.

This is response preservation, not redaction of model-generated content. A
future live approval must include retaining the public/synthetic review response
on the operator's existing local evidence path. Secret-loading and provider HTTP
errors remain sanitized. No new IAM access or logging service is introduced.

Tests cover malformed review output, the maximum response size, oversized or
non-byte inputs, excluded stages and roles, completion uncertainty, response
preservation through the runner, shutdown, and refusal to send a second request.

## Approval scope

Approve the exact source PR merge after all checks pass. It does not deploy or
invoke anything. Existing signed plans and their deployed source remain pinned;
the used Inspector plan must not be run again. Before a replacement Inspector
call, a separate recovery contract, budget, reviewed deployment and exact live
allowance are required. QA also remains disabled and requires its own fresh
free-tier qualification and live approval. Candidate PR #3 remains a draft.
