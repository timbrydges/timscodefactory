"""Only after owner approves the exact Google disclosure; never generates text."""
import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa_preflight import build, PreflightTransport
from prepare_google_qa_broker import SECRET_ARN, SECRET_VERSION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approved-count-request-sha256', required=True)
    args = parser.parse_args()
    plan = build(ROOT)
    if args.approved_count_request_sha256 != plan['count_request_sha256']:
        raise RuntimeError('approved request differs')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise RuntimeError('preflight requires a clean reviewed checkout')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    # Fixed persistent location: another output path cannot silently retry this run.
    directory = Path.home() / 'factory-evidence' / 'google-qa-preflight-001'
    directory.mkdir(parents=True, exist_ok=False)
    journal = directory / 'result.json'
    evidence = {'status': 'STARTED_NO_RETRY', 'source_commit': source,
        'count_request_sha256': plan['count_request_sha256'],
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'generation_calls': 0}
    journal.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    # This flag records a human-approved digest; it does not authenticate approval.
    # The operator must obtain approval before launching this script.
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name='ca-central-1')
    config = Config(connect_timeout=5, read_timeout=30, retries={'total_max_attempts': 1})
    try:
        if session.client('sts', config=config).get_caller_identity()['Account'] != '666730517561':
            raise RuntimeError('wrong AWS account')
        secret = session.client('secretsmanager', config=config).get_secret_value(
            SecretId=SECRET_ARN, VersionId=SECRET_VERSION, VersionStage='AWSCURRENT')
        key = secret['SecretString']
        result = PreflightTransport().run_once(root=ROOT, api_key=key)
        evidence.update(result)
    except Exception:
        evidence['status'] = 'FAILED_OR_UNCERTAIN_DO_NOT_RETRY'
        journal.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        raise RuntimeError('preflight failed or uncertain; inspect sanitized journal, do not retry') from None
    finally:
        key = None
        secret = None
    journal.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()
