# Isolated Inspector recovery runtime

PR #360 added the separate recovery allowance verifier. This change connects it
to an isolated workflow and a disabled-by-default Lambda entry point. It does
not create, package, deploy, enable or invoke a function.

The boundary accepts only the exact unqualified function ARN
`arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-inspector-recovery-001`,
the matching Lambda name and region, and at least 120 seconds remaining. Only
`inspector_recovery001_run_once` with an allowance is accepted; invocation fields
cannot supply keys, credentials, prices, readiness or activation configuration.
Missing/false execution flags reject before files, clients or signatures.

Deployment-owned `INSPECTOR_RECOVERY001_ACTIVATION.json` has an exact schema,
SHA-256 environment binding and source matching BUILD.json. It pins the candidate,
canonical reconstructed Builder context, execution-role credential route, active
owner enrollment and mandatory failed-review capture. The separate signed
allowance is verified before AWS clients exist and again before the permanent
recovery claim. The only database used is the separate recovery table.

The workflow reuses the fixed Sonnet transport and strict response parser. It
claims before retrieving the provider credential, rechecks expiry before sending,
sends once without retries, validates model/output/cost, and records conditional
completion. Results remain unsigned and carry no gate or release authority.
Provider failures expose only fixed stages. Bounded responses obtained before a
validation or completion failure are returned as untrusted failure evidence,
explicitly unaccepted and non-reusable. Completion uncertainty never resends.

Offline tests exercise real signatures and protocol parsing with simulated AWS
clients and HTTP responses: successful ordering, repeat refusal, old-allowance
rejection, disabled and wrong-runtime boundaries, changed activation material,
provider/credential/claim failures, expiry, failed-review capture and uncertain
completion. These tests make no AWS or model calls and do not prove live provider
access or deployed source integrity.

## Remaining deployment gates

Approve the exact source merge with the required owner override after CI passes.
Packaging, isolated least-privilege IAM/function templates, owner-signing workflow
integration, a shutdown runner, and their previews still need preparation and
verification. No existing signing workflow can authorize recovery implicitly.
Only the separately approved exact deployment and live plan may enable one call.
The original Pilot 002 Inspector attempt and every existing worker remain unchanged.
