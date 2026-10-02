# Google QA: prepared, not activated

Owner direction preserves three provider families: OpenAI plans/builds,
Anthropic inspects/reviews security, and Google performs QA. No fallback to
OpenAI is configured for QA.

On 2026-10-02, the connected AWS account's ca-central-1 Secrets Manager inventory
contained only the Factory OpenAI provider secret among Factory/Google/Gemini
names. Local Factory environment key names were also checked; no Google key was
found. Secret values were not read. The signed-in Google AI Studio showed a paid
Thought Engine project and a free Default Gemini Project. Neither existing key
was copied or repurposed.

## Credential setup verified, 2026-10-02

After the owner's explicit approval, a separate `Tims Software Factory QA` key
was created in Default Gemini Project (`gen-lang-client-0247455615`) and stored
in `tims-software-factory/provider/google/qa` in account 666730517561,
ca-central-1. Google Cloud displayed the key as Available and restricted to
Gemini API, with its own linked service account. The project remains Free tier.
No Google billing was attached, existing key changed, runtime reader granted,
or model called.

At 21:55:41 UTC, the AWSCURRENT value was read once per verification attempt
and matched against the created key's in-memory digest without printing the
stored value. The first read-only verification stopped because AWS omits
`KmsKeyId` for its default key; the corrected verification resolved the default
`alias/aws/secretsmanager` and confirmed AWS-managed encryption. Rotation and
replication are disabled and no resource policy was added. Temporary key and
clipboard values were cleared after verification. The secret was created through
the console, not CloudFormation; do not execute the old empty-secret template
against this existing name. Non-secret metadata is recorded in
`factory/evidence/google-qa-credential-setup-2026-10-02.json`.

The free project's data-use terms must be considered before approving a live
request; paid and free Gemini tiers have different data-use terms.

AWS storage uses the existing AWS-managed Secrets Manager key rather than a new
customer-managed KMS key. Standard secret storage is USD 0.40/month prorated,
plus metered API usage. Retaining the secret retains its storage charge.
Source checked 2026-10-02: https://aws.amazon.com/secrets-manager/pricing/

## Prepared integration

`scripts/prepare_google_qa.py OUTPUT.json` exclusively writes a pending request,
request hash and one-resource credential template. It never creates credentials,
reads a secret, enables a role or invokes a provider.

`factory_runtime.google_qa` renders the exact candidate-bound QA packet for
`gemini-3.8-flash` with one candidate, LOW thinking, 4096 output tokens, a fixed
JSON schema and no tools. Its transport accepts no caller-selected endpoint,
puts the credential in the header, disables proxies and redirects, caps response
bytes and makes one HTTP attempt per object. This local latch is not durable
duplicate protection. The component is not connected to a live Lambda handler.

Response parsing rejects another model, blocking, truncation, tool calls,
duplicate JSON fields and inconsistent/out-of-bounds usage. It includes thought
tokens in output accounting. Parsed results remain unauthenticated and have no
gate authority; parsing a mocked response does not qualify a live provider.

The official model documentation lists Gemini 3.8 Flash as stable, with LOW
thinking supported. Standard pricing observed 2026-10-02 is USD 0.75 per million
input tokens and USD 3.75 per million output tokens including thinking through
2026-12-31. A planning envelope of 32768 input and 4096 combined output tokens
would be USD 0.039936. This is not a reservation or authorization: exact-input
token preflight, output/thinking cap qualification, current model availability,
fresh price evidence, a separate owner-approved scope/budget and durable claims
are required before any generation. Existing allowances are not reused.

Sources checked 2026-10-02:
- https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash
- https://ai.google.dev/gemini-api/docs/pricing
- https://ai.google.dev/api/generate-content

Next, prepare broker-only secret access and Google egress,
durable one-attempt reservation, independently executed QA tests and signed
report publication. Security follows accepted QA. No signer enrollment,
scheduling, task transition or production release is part of this setup.
