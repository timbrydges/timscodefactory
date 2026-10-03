# Pilot 002 one-shot transports

`Pilot002Transport` adds disabled-by-default HTTPS transport for all three roles.
It is not imported by a live handler and does not load credentials, discover AWS
sessions, reserve a budget, authorize a call or calculate its price. The future
deployment-owned adapter must invoke it only after the workflow verifies a fresh
signed allowance and claims the fixed role in the permanent attempt ledger.

Construction reconstructs the exact task request from pinned source. Sending
requires those bytes and their digest. Routes are fixed to OpenAI Responses,
Google generateContent for the pinned Gemini model, and Bedrock Converse in
ca-central-1 for the pinned global Sonnet profile. It uses direct HTTPS with
certificate/hostname validation and no environment proxy discovery. Caller
fields cannot select hosts, paths, headers, TLS settings or retry behavior.

The transport sends once and never follows redirects. A thread-safe local latch
is consumed before credential validation/signing/connection, including failure.
It prevents duplicate sends through the same instance; it cannot replace the
permanent ledger across instances or process restarts. HTTP errors are discarded
without reading their bodies. Only successful uncompressed JSON responses up to
256 KiB are returned, and the connection is closed on success and failure.
Errors expose no raw provider exception or credentials. Socket operations have
a 90-second timeout; this is not an overall wall-clock deadline. A future runtime
must enforce its own invocation deadline without retrying ambiguous outcomes.

OpenAI and Google credentials are supplied in headers only. Inspector requires
frozen temporary AWS credentials supplied by the approved loader. Its canonical
SDK argument object is checked in full, then modelId is mapped to the fixed
Converse URI and remaining arguments become canonical JSON. Botocore SigV4
primitives sign the actual URI, body and headers; the ordinary DEBUG logging
path is avoided because it can include session tokens. A deterministic fixture
compares the resulting signature with standard botocore signing.

Returned bytes are not yet an authenticated completion record. Response parsing,
qualified pricing, transport-to-receipt binding, signed owner allowances,
deployment and live activation remain required. All current transport tests
replace the connection with an in-memory fake; no production credentials,
external requests, live compatibility test or model budget were used.

References: [Python HTTPSConnection](https://docs.python.org/3/library/http.client.html),
[Bedrock Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html),
[botocore signing implementation](https://github.com/boto/botocore/blob/develop/botocore/auth.py).
