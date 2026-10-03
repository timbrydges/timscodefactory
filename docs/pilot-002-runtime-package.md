# Pilot 002 disabled runtime package

`scripts/build_pilot002_runtime_package.py` creates a new ZIP outside the checkout
from a clean commit. Source is read from Git blobs, so worktree line endings and
ignored secrets cannot enter the package. An explicit module/material list includes
only Pilot 002's adapter dependency chain and pinned task evidence. Historical
provider handlers, signer enrollment and live pricing/activation files are absent.

The existing hash-locked Linux Python 3.12 x86_64 cryptography dependencies are
bundled. AWS botocore is provided by the target Lambda runtime; its observed version
is reported by the probe and must be reviewed with deployment evidence. Stable ZIP
timestamps, Unix modes, sorted entries and a per-file digest index support
reproducibility. The returned ZIP digest and source commit are the external
deployment anchors. The internal index is a corruption check, not a signature or
substitute for verifying the deployed code hash. Package outputs cannot overwrite
an existing file.

The handler is `factory_runtime.pilot002_runtime_probe.handler`. It requires
`FACTORY_PILOT002_EXECUTION_ENABLED=false` and a deployment-owned
`FACTORY_PILOT002_ROLE` of builder, inspector or qa. Its only accepted event has
kind `pilot002_runtime_probe`, the exact package source commit and matching role.
It verifies indexed file contents, pinned task material, imports the adapter
dependency chain and checks Ed25519 verification using a public RFC 8032 vector.
It reports versions and digests without constructing clients, loading secrets,
signing evidence, claiming attempts or calling providers.

There is deliberately no active dispatch branch. Setting the enable flag to true
or submitting an allowance/run event is rejected. This package can validate the
runtime foundation; a future reviewed runtime boundary, credentials, fresh
qualifications, owner-key enrollment, signed allowances and activation are still
needed for actual generation. No AWS resource or permission is created by building.

Tests cover all roles, altered/missing files, unsafe paths, event/flag substitutions,
deterministic archives, clean-source checks and overwrite protection. The Linux
Python 3.12 suite additionally builds actual locked wheels and invokes the probe
in an isolated extracted package. The Windows run skips that Linux-only check.
