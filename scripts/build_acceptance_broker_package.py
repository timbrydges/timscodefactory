"""Build a manifest-bound, disabled acceptance broker Lambda ZIP."""
from __future__ import annotations

import sys
from build_role_package import build, contract_paths


if __name__ == '__main__':
    build(sys.argv[1], extra_paths=contract_paths())
