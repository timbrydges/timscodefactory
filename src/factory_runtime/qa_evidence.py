"""Combine local tests and Google assessment without granting signing authority."""
import hashlib
from pathlib import Path

from factory_state.model import StateError
from factory_state.scope import canonical
from . import qa_execution
from .google_qa import parse_response
from .google_qa_records import parse_record
from .qa_execution import fixtures
from .review_preparation import validate_packet


def validate_execution(report, packet, *, root):
    validate_packet(packet, root=root)
    if not isinstance(report, dict) or packet['role'] != 'qa':
        raise StateError('QA execution evidence type differs')
    value = {k:v for k,v in report.items() if k != 'report_digest'}
    if (len(canonical(value)) > 65536 or
            report.get('report_digest') != 'sha256:'+hashlib.sha256(canonical(value)).hexdigest() or
            any(report.get(k) != packet[k] for k in ('candidate_commit','contract_digest','packet_digest')) or
            report.get('executed_source_sha256') != packet['files_sha256']['fingerprint.py'] or
            report.get('runner_sha256') != hashlib.sha256(Path(qa_execution.__file__).read_bytes()).hexdigest() or
            report.get('gate_authority') is not False or report.get('production_release_authorized') is not False or
            type(report.get('model_calls')) is not int or report['model_calls'] != 0 or
            type(report.get('case_count')) is not int or report['case_count'] != 18):
        raise StateError('QA execution evidence binding differs')
    cases = report.get('cases')
    expected = {name: {'case':name,'input_sha256':hashlib.sha256(data).hexdigest(),
                       'input_bytes':len(data),'expected_success':valid}
                for name,data,valid in fixtures()}
    expected.update({name:{'case':name,'expected_success':False} for name in
        ('no-argument','extra-argument','missing-file','directory-input')})
    if not isinstance(cases,list) or len(cases) != len(expected):
        raise StateError('QA execution cases missing')
    seen = set()
    for case in cases:
        if (not isinstance(case,dict) or not isinstance(case.get('case'),str) or
                case['case'] not in expected or case['case'] in seen or
                type(case.get('passed')) is not bool or
                canonical({k:v for k,v in case.items() if k!='passed'}) != canonical(expected[case['case']])):
            raise StateError('QA execution case differs')
        seen.add(case['case'])
    passed = all(c['passed'] for c in cases)
    status = 'LOCAL_QA_PASSED_UNSIGNED' if passed else 'LOCAL_QA_FAILED_UNSIGNED'
    if report.get('status') != status:
        raise StateError('QA execution status contradicts cases')
    return passed


def combine(report, packet, *, root, google_response=None, google_record=None):
    if google_response is not None and google_record is not None:
        raise StateError('supply one Google evidence representation, never two')
    passed = validate_execution(report, packet, root=root)
    assessment = None if google_response is None else parse_response(google_response, packet, root=root)
    evidence_format = None if google_response is None else 'RAW_PROVIDER_RESPONSE'
    evidence_bytes = google_response
    if google_record is not None:
        assessment = parse_record(google_record, packet, root=root)
        evidence_format = 'RECORDED_UNSIGNED_PROVIDER_RESULT'
        evidence_bytes = canonical(assessment)
    verdict = ('REJECTED' if not passed or (assessment and assessment['assessment']['verdict']=='REJECTED')
               else 'PENDING_GOOGLE' if assessment is None else 'READY_FOR_INDEPENDENT_PUBLICATION_REVIEW')
    return {'status':'UNSIGNED_QA_EVIDENCE_BUNDLE', 'review_status':verdict,
        'candidate_commit':packet['candidate_commit'], 'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'], 'local_report_digest':report['report_digest'],
        'local_cases_passed':passed, 'google_assessment':assessment,
        'google_response_digest':None if evidence_bytes is None else 'sha256:'+hashlib.sha256(evidence_bytes).hexdigest(),
        'google_evidence_format':evidence_format,
        'gate_authority':False, 'production_release_authorized':False,
        'requires':['Trusted executor provenance','Fresh QA lease','Independent signer publication','Controller verification']}
