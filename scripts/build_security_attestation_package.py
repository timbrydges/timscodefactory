"""Build clean hash-locked Linux package for fixed-candidate Security static attestation."""
import sys
from build_role_package import build

if __name__=='__main__':
    build(sys.argv[1],extra_paths=(
        'factory/evidence/builder-006-pending-implementation-inspection.json',
        'factory/evidence/inspector-014-signed-implementation-review-2026-10-02.json',
        'factory/evidence/qa-security-bootstrap-live-proof-2026-10-02.json',
        'factory/evidence/qa-gate-001-live-proof-2026-10-03.json',
        'factory/evidence/qa-executor-signers-2026-10-03.json'))
