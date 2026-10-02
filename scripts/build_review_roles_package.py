"""Build the exact clean source for disabled QA/security identity probes."""
import sys
from build_role_package import build

if __name__ == '__main__':
    build(sys.argv[1])
