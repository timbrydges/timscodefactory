"""Write pending QA/security packets exclusively; no clients, calls or grants."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.review_preparation import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('qa', 'security'))
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    packet = prepare(ROOT, role=args.role)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(packet, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: packet[k] for k in ('status', 'role', 'packet_digest', 'model_calls_authorized')}))


if __name__ == '__main__':
    main()
