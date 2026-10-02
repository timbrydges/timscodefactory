# Google QA preflight approval boundary

The next external action is qualification, not generation. Offline preparation
reconstructs the pinned candidate, contract, system instruction and output schema.
The countTokens request embeds the complete generateContentRequest including its
model name; counting only source text would omit instructions and schema.

After explicit owner approval, the runner reads only the previously approved
Google secret version from AWS, authenticates to the fixed Google endpoint in a
header, gets the exact model metadata once, then sends one countTokens request.
It never calls generateContent. Wrong metadata prevents candidate transmission.
Neither call retries or follows redirects; proxy environment variables are ignored.
Response bodies and credentials are not logged. A fixed, exclusive CloudShell
journal directory prevents an ordinary rerun even after a timeout or restart.
It is an operator guard, not a distributed authorization or monetary ledger.

Prepare locally with `python scripts/prepare_google_qa_preflight.py OUT.json`.
Review the full request and digest in that file. Only after owner approval, use
`python scripts/run_google_qa_preflight.py --approved-count-request-sha256 DIGEST`
from a clean reviewed CloudShell checkout. The digest argument records approval;
it does not authenticate the owner. Never delete its journal to retry. Inspect
an uncertain outcome before seeking a new authorization.

## Disclosure requiring approval

Recipient: Google Gemini API, project `gen-lang-client-0247455615`, last observed
Free tier. Data: the candidate source and tests, contract, review instructions,
binding identifiers and JSON schema. The credential goes only to Google's fixed
HTTPS API as an authentication header. No OpenAI or Anthropic credentials are read.

Google's unpaid-service terms permit use of submitted content for improvement
and human review, and prohibit sensitive, confidential or personal information.
Obtain approval for this exact disclosure; do not assume key-creation approval
or the disabled AWS deployment authorized transmitting review material.
No Google billing link, new key, model-generation budget, live Lambda activation,
task transition, signer enrollment or schedule change is included.

## What success does not prove

Token count is a preflight observation, not a generation bill or a signed verdict.
It does not qualify the combined thought/output cap, reserve money, acquire the
generation attempt, or establish independent execution of candidate tests.
Those gates remain required before a separately approved live pilot. The deployed
shared-capacity broker still has no generation branch and remains disabled.

References checked 2026-10-02:
- https://ai.google.dev/api/tokens
- https://ai.google.dev/api/models
- https://ai.google.dev/gemini-api/terms
