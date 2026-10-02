"""Prepare an exact external-disclosure proposal offline; no credential access."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa_preflight import build

if __name__ == '__main__':
    plan = build(ROOT)
    with Path(sys.argv[1]).open('x', encoding='utf-8') as stream:
        json.dump(plan, stream, indent=2)
    print(json.dumps({k: plan[k] for k in ('status', 'count_request_sha256',
        'count_request_bytes', 'maximum_http_requests', 'generation_calls')}))
