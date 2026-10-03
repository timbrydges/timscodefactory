import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_runtime.qa_execution import execute
from factory_runtime.qa_evidence import combine
from factory_runtime.review_preparation import BINDING, prepare
from factory_runtime.google_qa import MODEL


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet=prepare(ROOT,role='qa')
        cls.report=execute(ROOT)

    def response(self, verdict='ACCEPTED'):
        assessment={**{k:self.packet[k] for k in BINDING},'verdict':verdict,'rationale':'Review','findings':[]}
        return json.dumps({'modelVersion':MODEL,'candidates':[{'finishReason':'STOP',
            'content':{'role':'model','parts':[{'text':json.dumps(assessment)}]}}],
            'usageMetadata':{'promptTokenCount':2931,'candidatesTokenCount':100,'totalTokenCount':3031}}).encode()

    def rehash(self, report):
        report['report_digest']='sha256:'+hashlib.sha256(canonical({k:v for k,v in report.items() if k!='report_digest'})).hexdigest()
        return report

    def test_google_is_required_and_neither_result_grants_gate_authority(self):
        pending=combine(self.report,self.packet,root=ROOT)
        self.assertEqual(pending['review_status'],'PENDING_GOOGLE')
        result=combine(self.report,self.packet,root=ROOT,google_response=self.response())
        self.assertEqual(result['review_status'],'READY_FOR_INDEPENDENT_PUBLICATION_REVIEW')
        self.assertFalse(result['gate_authority'])
        self.assertFalse(result['production_release_authorized'])

    def test_either_tests_or_google_can_reject(self):
        report=copy.deepcopy(self.report)
        report['cases'][0]['passed']=False
        report['status']='LOCAL_QA_FAILED_UNSIGNED'
        self.rehash(report)
        self.assertEqual(combine(report,self.packet,root=ROOT,google_response=self.response())['review_status'],'REJECTED')
        self.assertEqual(combine(self.report,self.packet,root=ROOT,google_response=self.response('REJECTED'))['review_status'],'REJECTED')

    def test_rehashed_missing_duplicate_wrong_candidate_and_forged_authority_rejected(self):
        for change in ('missing','duplicate','candidate','runner','authority','status'):
            report=copy.deepcopy(self.report)
            if change=='missing': report['cases'].pop()
            elif change=='duplicate': report['cases'][0]=report['cases'][1]
            elif change=='candidate': report['candidate_commit']='a'*40
            elif change=='runner': report['runner_sha256']='a'*64
            elif change=='authority': report['gate_authority']=True
            else: report['status']='LOCAL_QA_FAILED_UNSIGNED'
            self.rehash(report)
            with self.assertRaises(StateError): combine(report,self.packet,root=ROOT)


if __name__=='__main__': unittest.main()
