"""Read the fixed Google QA ledger once; never read secrets or invoke a model."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa_reconcile import observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source-commit', required=True)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name='ca-central-1')
    config = Config(connect_timeout=5, read_timeout=30, retries={'total_max_attempts': 1})
    with args.output.open('x', encoding='utf-8') as output:
        try:
            if session.client('sts', config=config).get_caller_identity()['Account'] != '666730517561':
                raise RuntimeError('wrong AWS account')
            result = observe(session.client('dynamodb', config=config), root=ROOT,
                source_commit=args.expected_source_commit, observed_at=datetime.now(timezone.utc))
        except Exception:
            output.write(json.dumps({'status':'READ_FAILED_OR_EVIDENCE_INVALID',
                'retry_authorized':False,'generation_authorized':False,'gate_authority':False}))
            raise RuntimeError('Google reconciliation failed; inspect scope without invoking a model') from None
        output.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
