"""Build an exact manifest-bound acceptance controller ZIP."""
import sys

from build_role_package import build, contract_paths


if __name__ == '__main__':
    build(sys.argv[1], extra_paths=contract_paths())
