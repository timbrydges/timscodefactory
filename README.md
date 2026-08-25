# Tim's Software Factory

Owner-controlled, fail-closed automation for building and releasing software with multiple independent AI roles.

This repository is the durable system of record. Runtime coordination data lives in the adjacent AWS state store defined under `infra/aws`; agents never mutate authoritative state directly.

The control-plane repository is intentionally public so GitHub can enforce the required ruleset and production-approval gates without Enterprise Cloud. Product repositories may remain private; secrets, runtime state, customer data, and proprietary application code do not belong here.

Tim Brydges is the sole human Factory Owner and ultimate authority. He may approve his own work, bypass any gate, intervene at any stage, and pause, stop, resume, or override the Factory without outside approval. Agent independence rules remain mandatory for agents and are never authority over Tim. See [`docs/OWNER_AUTHORITY.md`](docs/OWNER_AUTHORITY.md).

## Control plane

- `factory/registry.yaml` binds the F3.1 registry to `timbrydges/timscodefactory`.
- `factory/roles/` contains the 11 machine-readable role contracts.
- `factory/profiles/` contains provider, credential, network, evidence, and controller-integrity profiles.
- `scripts/validate_registry.py` validates schemas, bindings, independence, least privilege, and manifest integrity.
- `scripts/preflight.py` executes the static and live F3.1 preflight checks.
- `infra/aws/` provisions the adjacent DynamoDB state store, immutable release bucket, and GitHub OIDC release role.
- `.github/workflows/` enforces registry CI, preflight, and the production OIDC release path.

## Fail-closed bootstrap

```bash
python -m pip install -r requirements-dev.txt
python scripts/build_manifest.py --check
python scripts/validate_registry.py
python scripts/preflight.py --mode static
python -m unittest discover -s tests -v
```

Production releases remain disabled until the protected `production` environment and the AWS outputs are bound to GitHub variables. The environment permits deployment only from `main`. Agent-initiated releases require Tim's approval; Tim may approve his own run or use the administrator bypass. No other actor may bypass the release gate.
