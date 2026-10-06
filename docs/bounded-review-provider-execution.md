# Bounded provider execution

The fresh provider backend connects the exact signed scope and permanent claims
to fixed OpenAI Responses, Bedrock Converse, and Google Gemini routes. It is
disabled by default and has no Lambda entrypoint or deployment permissions.

Job bytes bind the two candidate files and source/contract/test-proof pins.
Their digest is calculated before embedding the expected output bindings in
the provider request, avoiding a self-referential input hash. Serialization and
response-envelope decoding reuse pure codecs; historical task allowances and
attempt records are never used. The complete prepared request is reconstructed
and checked before transport. Models, hosts, paths, TLS, response bounds, no
redirects and no retries are fixed by the adapter.

This first bounded controller task reproduces the pinned tested candidate. The
Builder must return exactly those files. It cannot substitute a changed candidate
under an old test proof. Inspector and QA return their own bound verdicts;
REJECTED output may be retained and signed for audit but cannot pass the
deployment-owned progressor. This is not a general arbitrary-code build grant.

Before each effect the backend verifies current persisted task/lease/scope,
fresh trusted keys, owner provider allowance and independent test evidence.
Controller and role share the exact RESERVED hold; only the remote role has a
credential loader. The permanent send claim is consumed before credential
loading. A second task/scope check after loading blocks a newly paused task.
Provider usage and cost must fit the qualified bound before completion; the
full hold remains HELD. Any uncertain failure preserves the claim and reports
only its stage, without provider error text or credentials.

Tests use real Ed25519 signatures, Moto transactions and a synthetic HTTPS peer.
No provider was contacted. Live use still requires fresh authenticated main test
proof, current price/readiness evidence, exact signing/credential configuration,
new isolated claim resources, and a reviewed disabled deployment before activation.
