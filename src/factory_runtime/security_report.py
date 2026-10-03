"""Fixed-candidate static observations, not a comprehensive security verdict.

Never imports or executes candidate code. All observations bind exact source
bytes and a previously verified QA gate; report data cannot authorize a gate.
"""
import ast
import base64
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers
from .review_preparation import prepare, validate_packet, pinned, digest
from .qa_gate import HISTORICAL_REGISTRY, HISTORICAL_REGISTRY_SHA

QA_PROOF = 'factory/evidence/qa-gate-001-live-proof-2026-10-03.json'
QA_PROOF_SHA = '0c82155a62a47279fad79f9d56c0815e85efd829500100dd76a2d1159a405048'


def execute(root, *, packet=None):
    packet = prepare(root, role='security') if packet is None else packet
    validate_packet(packet, root=root)
    if packet['role'] != 'security':
        raise StateError('Security report requires the pinned Security packet')
    proof = pinned(root, QA_PROOF, QA_PROOF_SHA)
    pinned(root, HISTORICAL_REGISTRY, HISTORICAL_REGISTRY_SHA)
    result = proof['signed_result']; payload = result['payload']
    issued = datetime.fromtimestamp(payload['issued_at'], timezone.utc)
    signed_digest = SignedScopeStore('unused', None,
        load_trusted_signers(root/HISTORICAL_REGISTRY, now=issued))._verify(
            payload, base64.b64decode(result['signature_base64'], validate=True),
            'qa_engineer_service', issued)
    if (signed_digest != proof['signed_payload_digest'] or proof['state'] != 'SECURITY_REVIEW' or
            proof['version'] != 14 or payload['candidate_commit'] != packet['candidate_commit'] or
            payload['contract_digest'] != packet['contract_digest']):
        raise StateError('Security prerequisite QA proof differs')
    tree = ast.parse(packet['untrusted_material']['files']['fingerprint.py'])
    imports = sorted(n.name for item in ast.walk(tree) if isinstance(item, ast.Import) for n in item.names)
    dynamic = sorted(n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and
                     isinstance(n.func, ast.Name) and n.func.id in {'eval','exec','compile','__import__'})
    if imports != ['hashlib','json','sys'] or dynamic:
        raise StateError('Pinned Security source import or execution surface differs')
    material = {
        'status':'STATIC_FINDINGS_RECORDED_UNSIGNED', 'role':'security',
        'candidate_commit':packet['candidate_commit'], 'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'], 'files_sha256':packet['files_sha256'],
        'qa_gate_payload_digest':signed_digest, 'qa_gate_proof_digest':'sha256:'+QA_PROOF_SHA,
        'method':'AST inspection and manual observations bound to exact pinned source; candidate not executed',
        'observations':{'direct_imports':imports,'dynamic_execution_calls':dynamic,
            'read_request_bytes':4097,'accepted_input_bytes':4096,'utf8_errors':'strict',
            'os_error_response':'error: unable to read input file',
            'output_contains_full_input':True},
        'findings':[
            {'id':'unrestricted-input-path','disposition':'requires-caller-isolation',
             'detail':'The CLI opens the supplied path and follows symlinks. It does not restrict reads to a workspace.'},
            {'id':'blocking-special-files','disposition':'requires-host-timeout',
             'detail':'The byte limit does not bound open/read time; a FIFO or device may block. No regular-file check or timeout is present.'},
            {'id':'input-disclosure','disposition':'requires-output-handling',
             'detail':'Successful JSON output includes the entire decoded input. Callers must prevent sensitive file inputs and unintended output disclosure.'}],
        'limitations':['No dynamic security testing or candidate execution',
            'No proof of host isolation, filesystem containment, dependency integrity or absence of all vulnerabilities',
            'Historical QA signature is provenance, not a current lease or execution authorization'],
        'model_calls':0,'candidate_executions':0,'task_state_writes':0,
        'gate_authority':False,'production_release_authorized':False}
    return {**material,'report_digest':digest(material)}


def validate_execution(report, packet, *, root):
    if canonical(report) != canonical(execute(root, packet=packet)):
        raise StateError('Security report differs from exact source observations or suppresses findings')
    return True
