# Independent executable QA and evidence assembly

The local runner executes only the exact inspected fingerprint candidate from
the hash-pinned Builder packet. It reconstructs the review packet and validates
the source hash before copying the program into a fresh temporary directory.
It requires Python 3.12, removes provider credentials from the child environment,
uses no shell, disconnects stdin and limits each child to five seconds.
Python `-I` is import/environment isolation, not an operating-system sandbox.
This must never be extended into a general arbitrary-code executor.

Fourteen input fixtures cover exact size boundaries, multibyte boundary crossing,
JSON escaping, BOM, combining characters, NUL/control bytes, UTF-8 surrogates,
overlong encodings and truncated/invalid code points. Every fixture runs twice
and compares exact output bytes, return code and stderr. Four additional cases
test missing/extra arguments, a missing file and a directory path. Rejections
must produce no stdout and a concise one-line error, never a traceback.

Run `python scripts/run_independent_qa.py OUT.json` with Python 3.12. The output
path is exclusive and cannot overwrite earlier evidence. The report binds the
candidate, contract, packet, executed source, runner digest, runtime and cases.
The required Builder test command is separate; these cases do not replace it.

Use `python scripts/prepare_qa_evidence_bundle.py REPORT.json BUNDLE.json` to
prepare a PENDING_GOOGLE bundle. A future saved Google response can be supplied
with `--google-response RESPONSE.json`; this reads a bounded local file and makes
no API call. Incorrect candidate bindings, changed cases, duplicate/missing cases,
contradictory pass status and self-asserted gate authority are rejected. Failed
tests or a rejected Google assessment produce REJECTED. Two passes produce only
READY_FOR_INDEPENDENT_PUBLICATION_REVIEW, never an accepted Factory gate.

For a saved broker result, use `--google-record RECORD.json` instead. This file
contains the workflow's `response` object (also stored in the attempt ledger),
not its outer completion envelope or a recreated raw Google response. The same
strict record parser is used by reconciliation and evidence assembly. It rejects
duplicate fields, extra fields, wrong models/candidates/roles, invalid usage and
invented authority. The bundle labels the evidence representation and hashes the
canonical recorded object; a raw response instead retains its original byte hash.
The two input options are mutually exclusive. Neither proves provider provenance,
signs a gate, performs another model call or releases the spending hold.

Both artifacts are unsigned local evidence. Hashes bind content, not execution
authenticity. A future publisher must establish trusted executor provenance and
a fresh QA lease, then sign and submit through controller verification. No signer,
state transition, provider request, spending reservation or production release is
authorized by this runner, validator or bundle builder.

## Isolated runtime preparation

`factory_runtime.qa_execution_runtime.handler` accepts only an exact source-bound
`qa_execute_unsigned` event for the fixed candidate, QA role and literal false
operational flag. It has no cloud client, credential, model or KMS signing path.
The Linux package builder includes the three pinned review-evidence files.
Deployments should modify only QaFunction and add a new QaExecutionVersion in the
existing review bootstrap stack. Leave QaVersion untouched, preserving every
IAM/KMS/security resource and old immutable version. Adding Retain policies during
a version replacement did not prevent a ReplaceAndDelete change-set preview;
reject that preview and use an additive version resource instead. Pin the package
S3 version and code hash; verify the deployed version
before one synchronous execution without retries. Results remain unsigned.

`scripts/prepare_qa_execution_deployment.py CURRENT_TEMPLATE PACKAGE_MANIFEST
OUTPUT --object-version VERSION` now prepares that additive update offline.
It pins the package digest and immutable S3 object version, derives a new version
logical ID from the package hash, and preserves all existing parameters, outputs
and resources except the QA function's Code, Handler and Timeout. An existing
version for the same package is rejected instead of recreated.

Before execution, use its `validate_changes` function with the actual proposed
template from CloudFormation, the complete DescribeChangeSet response and exact
stack ARN. All existing parameters must use their previous values. Only an
in-place QA function update and one added version are accepted; replacements,
deletions, permission changes, partial pages, duplicated changes and changed
templates are rejected. This validator does not create or execute a change set,
prove package contents, invoke QA, sign evidence or authorize a model call.

## Observed AWS execution

The evidence in `factory/evidence/qa-execution-live-proof-2026-10-03.json`
records one execution of immutable QA version 2: all 18 cases passed on Linux
Python 3.12.14. Version 1 and the Security function were preserved and IAM was
verified unchanged. The bundle remains PENDING_GOOGLE; this operator observation
is not a signed executor attestation and cannot authorize a task transition.
