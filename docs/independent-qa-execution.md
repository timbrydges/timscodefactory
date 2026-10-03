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
Deployments should change only QaFunction and QaVersion in the existing review
bootstrap stack, preserving every IAM/KMS/security resource and old immutable
versions. Pin the package S3 version and code hash; verify the deployed version
before one synchronous execution without retries. Results remain unsigned.
