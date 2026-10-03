# Pilot 002 scoped runtime access preview

The preparation adds three standalone inline-policy resources to the existing
disabled runtime stack. The nine existing resources must match the previously
reviewed template byte-for-byte after canonical serialization. Code, handlers,
environments, role trust, logs and concurrency remain unchanged. The validator
accepts only three policy additions; replacements, updates to existing resources,
extra resources, wrong-account previews and incomplete results are rejected.

Each role may PutItem and UpdateItem only its own permanent Pilot 002 attempt key.
No DeleteItem, Scan, batch, task-state or cross-role access is granted. A non-null
LeadingKeys condition is required. Conditional writes and the no-retry workflow
remain necessary; IAM permissions alone do not implement the attempt protocol.

Builder can read only the existing OpenAI acceptance secret. Its customer-managed
KMS key requires an additional Decrypt grant, constrained to Secrets Manager in
ca-central-1, that secret ARN and version ebb6cc21-2df9-4b06-8f55-2b0661f27f69.
The key policy already delegates authorization to account IAM; it is not changed.
QA can read only the existing Google QA secret, which uses aws/secretsmanager.
QA's immutable VersionId is enforced by the reviewed entry point and activation
bundle, not by a version-specific IAM condition. No key value is read for this
preview, and metadata does not establish credential validity or project ownership.

Inspector receives only non-streaming InvokeModel permission for the exact global
Sonnet 4.5 profile and its two foundation-model resources. The source-region and
global-model conditions require the exact profile. This follows AWS's
[global inference IAM requirements](https://docs.aws.amazon.com/bedrock/latest/userguide/global-cross-region-inference.html).
Builder's encryption conditions follow the documented
[Secrets Manager encryption context](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html).

The old Builder broker's credential-route setting is empty. This preview does not
change it, reactivate historical brokers, rotate credentials or declare readiness.
The new entry point will use an explicitly reviewed ARN and immutable version.

## Approval boundary

Creating and validating an unexecuted change set does not grant these permissions.
The owner must approve the exact PR override and AWS change set before execution.
After approval, verify the three new inline policies and unchanged function
code/handler/flags/concurrency, existing controls and unused attempt rows.
No function invocation or secret-value read is part of that deployment approval.

All functions still use the probe-only package, explicit disabled flags and zero
concurrency. Live operation additionally needs a reviewed activation package,
fresh pricing/readiness evidence, owner enrollment and exact signed allowances,
plus separately approved handler, timeout and concurrency changes. This preview
does not authorize model calls, schedule activation, retries, merge or release.
