"""Run offline independent checks of the pinned candidate, producing unsigned evidence."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.qa_execution import execute

if __name__ == '__main__':
    # Reserve the evidence path before executing; never overwrite a prior run.
    with Path(sys.argv[1]).open('x', encoding='utf-8') as output:
        report = execute(ROOT)
        output.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','candidate_commit','case_count','report_digest','gate_authority')}))
    sys.exit(0 if report['status']=='LOCAL_QA_PASSED_UNSIGNED' else 1)
