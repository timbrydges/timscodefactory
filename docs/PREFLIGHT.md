# F3.1 preflight

The preflight suite has four layers:

- **Static:** schema, registry, profile, manifest, repository, and OIDC bindings.
- **Adversarial:** unknown authority, missing profiles, provider collision, self-approval, expired lease, forged evidence, protected-path writes, registry tampering, unsigned releases, authority-changing provider swaps, and controller bypass.
- **Recovery:** owner pause behavior and deterministic AI-independent rollback.
- **Live:** active GitHub main ruleset plus a production environment requiring Tim's independent approval and an explicit main-only deployment policy.

Run locally:

```bash
python scripts/build_manifest.py --check
python scripts/validate_registry.py
python scripts/validate_workflows.py
python scripts/preflight.py --mode static
python -m unittest discover -s tests -v
```

Run `preflight` manually in GitHub with `live=true` only after the ruleset and environment exist. Pilot mode is forbidden until PF-01 through PF-20 all pass.
