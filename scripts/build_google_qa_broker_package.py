"""Build clean, pinned source for the disabled Google broker boundary."""
import sys
from build_role_package import build

if __name__ == '__main__':
    build(sys.argv[1], extra_paths=(
        'factory/evidence/builder-006-pending-implementation-inspection.json',
        'factory/evidence/inspector-014-signed-implementation-review-2026-10-02.json',
        'factory/evidence/qa-security-bootstrap-live-proof-2026-10-02.json',
        'factory/evidence/google-qa-credential-setup-2026-10-02.json'))
