"""Build a manifest-bound, disabled acceptance broker Lambda ZIP."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from build_role_package import ROOT, build


def contract_paths(root: Path = ROOT) -> tuple[str, ...]:
    contract_path = 'factory/autonomy/operating-contract.yaml'
    schema_path = 'factory/schemas/autonomy-operating-contract.schema.json'
    contract = yaml.safe_load((root / contract_path).read_text(encoding='utf-8'))
    paths = {contract_path, schema_path, contract['approval']['evidence'],
             contract['acceptance_target']['evidence'], contract['pricing_reference']['evidence']}
    paths.update(gate['evidence'] for gate in contract['activation']['verified_gates'].values())
    manifest = (root / 'MANIFEST.sha256').read_text(encoding='utf-8')
    tracked = {line.split('  ', 1)[1] for line in manifest.splitlines()}
    for name in paths:
        path = Path(name)
        if (path.is_absolute() or '..' in path.parts or path.as_posix() not in tracked or
                not (root / path).is_file()):
            raise RuntimeError('broker package contract evidence is missing from manifest')
    return tuple(sorted(paths))


if __name__ == '__main__':
    build(sys.argv[1], extra_paths=contract_paths())
