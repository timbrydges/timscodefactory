# Pilot 002 provider protocols

Offline request serialization and response parsing now cover the three pinned
roles: OpenAI Builder, Bedrock Sonnet Inspector and Google Gemini QA. Requests
are reconstructed from the pinned task packets. No credentials, network client,
attempt claims, live handler or deployment changes are included.

OpenAI uses Responses JSON-object output, disabled response storage/background
processing/streaming, no tools, standard service tier and explicit caching with
no breakpoints. Inspector uses Converse plain text JSON with no tools. Google
uses one JSON candidate with LOW thinking and no exposed thoughts. Exact output
task, packet and candidate bindings are still checked by the existing parsers.

The canonical request is the complete OpenAI/Google JSON body or the complete
Converse SDK argument object, including modelId. Future transport must preserve
this serialization contract and bind the fixed provider endpoint/model. Google
model selection belongs to its fixed endpoint, not its body. A JSON byte count
is not a qualified input-token bound.

The parser rejects incomplete/refused/tool responses, wrong echoed model IDs,
ambiguous answers, malformed JSON, duplicate fields, invalid UTF-8, invalid token
counts and inconsistent totals. OpenAI output usage already includes reasoning;
Google candidate and thought counts are added once. Cache usage, new usage
fields and non-text modality details require separate qualification and fail
closed. The parser bounds observed input at 32768 tokens and combined output at
4096 tokens. Those are validation limits, not proof that a provider will enforce
every bound before billing, especially Google's separate thought accounting.

Results are explicitly unauthenticated and contain no dollar cost. Converse
does not echo the invoked model; transport must prove the exact profile used.
Response model strings from other providers also do not authenticate a response.
These codecs intentionally do not implement the workflow adapter interface.
Disabled fixed-route transports are described in `pilot-002-transports.md`.
Authenticated receipts, fresh full-request cost
qualification, model/parameter availability, Google billing/data-use readiness,
signed allowances and live activation remain required. Existing provider keys
and historical approvals are untouched. Tests use local synthetic envelopes;
there has been no provider compatibility smoke call.

Protocol references checked during implementation:

- [OpenAI Responses](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
- [AWS Bedrock Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)
- [Google GenerateContent](https://ai.google.dev/api/generate-content)
