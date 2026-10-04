# Pilot 002 reviewer owner-signing preparation

PR #353 was merged at `f0ccc35737cd3f1228076aa030113677beb340c1` and its exact
change set executed once. The saved deployment evidence records UPDATE_COMPLETE,
the expected Inspector/QA package hashes, and all three workers disabled with
reserved concurrency zero. No Lambda invocation or model call occurred.

The owner workflow previously supported only the Builder Pilot 002 allowance.
The reviewer job adds an explicitly selected Inspector or QA signing path using
the existing isolated owner identity, production environment, first-run-only
guard, hash-locked dependencies, and one-attempt SDK configuration. Reviewer
inputs exclude every other signing/canary job, including partial input cases.
There are no new IAM grants, runtime changes, or automatic workflow triggers.

The signer accepts only a separately reviewed committed plan at
`factory/evidence/pilot-002-<role>-live-review-candidate.json` and its exact
owner-approved digest. No such live plan is included in this change. It pins:

- Runtime source `d9c75eb8b59c3c6bda508557224fd92354f8d34c`.
- Candidate `09c789a902377cb095c20abae89459c4cec3e89e` in acceptance PR #3.
- Each exact provider request already token-counted on October 4.
- The Inspector execution-role route or the verified immutable Google secret
  version and raw-key format. Secret contents are never included.
- Explicit reviewer first-generation failure-risk acceptance. Token counting
  does not prove generation access.
- One provider call, no retries, USD 0.25 held per role, no Factory state writes,
  gate authority, or release authority.

QA accepts only the existing zero-dollar free-tier qualification. Its billing
observation and qualification still expire within five minutes. Paid fallback,
billing linkage, and extending freshness are not authorized by this change.
Inspector still requires fresh reviewed pricing and request bounds. Validation
checks bindings and freshness; it cannot independently prove pricing, billing,
credential access, or the truth of supplied evidence. Those require live
read-only observations before an exact plan is approved.

The test context is the canonical reconstruction of the successful Builder's
parsed file result, with bytes matching the published candidate. It is not the
original raw provider response. Its SHA-256 is
`bc95e2daa9f825dd6128008b420051729431524439fdce01d515499c4d93457a`;
the original raw response digest was
`3df84e226f7f08f4ca5551b12335bcc77353ad1539e7c9a8028d1ff6b39a6195`.
Synthetic test prices/readiness are explicitly fixtures, never live evidence.

## Next approval boundary

Approve merging this owner-signing workflow change after CI passes. That merge
does not sign an allowance, deploy activation material, enable concurrency, or
run a model. Each later signing dispatch needs an exact approved plan digest.
Each activation needs verified deployment and trigger audits, unconsumed ledger
entries, current pricing/readiness, explicit shared-concurrency acceptance, and
an approved one-call runner with verified disablement on completion or failure.
Candidate merge/release and autonomous scheduling remain outside this scope.

If signing returns an uncertain result, reconcile the retained artifact and KMS
audit trail; never rerun the workflow automatically. The permanent runtime
per-task/per-role ledger remains the provider-call guard across signing runs.
