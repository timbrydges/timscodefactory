# F3.1 preflight

The preflight suite has four layers:

- **Static:** schema, registry, profile, manifest, repository, and OIDC bindings.
- **Adversarial:** unknown authority, missing profiles, provider collision, agent self-approval, expired lease, forged evidence, protected-path writes, registry tampering, unsigned releases, authority-changing provider swaps, and unauthorized dispatch.
- **Recovery:** executable owner pause behavior and deterministic AI-independent rollback transaction generation.
- **Live:** active GitHub main ruleset with Tim's always-on bypass, an approval-free owner production environment restricted to `main`, and the exact immutable repository-ID OIDC prefix.

GitHub only returns `bypass_actors` to a caller that can write the ruleset. The
workflow `GITHUB_TOKEN` cannot receive that permission. PF-19 therefore validates
the complete live ruleset exposed to the workflow and binds Tim's owner-authenticated
bypass observation to the live ruleset ID and `updated_at` value. Any ruleset change
invalidates that observation and fails closed until Tim verifies it again.

Run locally:

```bash
python scripts/build_manifest.py --check
python scripts/validate_registry.py
python scripts/validate_workflows.py
python scripts/preflight.py --mode static
python -m unittest discover -s tests -v
```

The complete preflight runs automatically after every push to `main`. It can also
be dispatched manually with `live=true`. Pilot mode is forbidden until PF-01
through PF-21 all pass.
