import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime import pilot002_packets as p
from factory_runtime.pilot002_bootstrap import PINNED
from factory_state.model import StateError
from factory_state.scope import canonical


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in [*PINNED, p.BASELINE]:
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        self.packet = p.builder_packet(self.root)
        self.reply = {'task_id':self.packet['task_id'], 'packet_digest':self.packet['packet_digest'],
            'files':{'fingerprint.py':'# candidate, never execute\n', 'tests/test_fingerprint.py':'# bounded tests\n'}}
        self.raw = canonical(self.reply)
        self.commit = 'a'*40

    def review(self, role='qa', raw=None, commit=None):
        return p.review_packet(self.root, role=role, builder_response=raw or self.raw, candidate_commit=commit or self.commit)

    def assessment(self, role='qa'):
        packet = self.review(role)
        return {**{k:packet[k] for k in p.REVIEW_BINDINGS}, 'verdict':'ACCEPTED','rationale':'Checked supplied text only.','findings':[]}

    def parse_review(self, value, role='qa'):
        return p.parse_review(canonical(value),root=self.root,role=role,builder_response=self.raw,candidate_commit=self.commit)

    def test_baseline_is_pinned_and_packet_deterministic(self):
        self.assertEqual(self.packet,p.builder_packet(self.root))
        self.assertEqual(self.packet['model_id'],'gpt-5.6-sol')
        self.assertLess(len(canonical(self.packet)),p.LIMIT)
        baseline=self.root/p.BASELINE
        baseline.write_bytes(baseline.read_bytes()+b' ')
        with self.assertRaises(StateError): p.builder_packet(self.root)

    def test_exact_two_files_and_response_bindings_required(self):
        for change in ({'packet_digest':'sha256:'+'f'*64},{'task_id':'old-task'},
                       {'files':{'../fingerprint.py':'x','tests/test_fingerprint.py':'x'}},
                       {'files':{**self.reply['files'],'README.md':'extra'}}, {'extra':True}):
            with self.subTest(change=change), self.assertRaises(StateError):
                p.parse_builder(canonical({**self.reply,**change}),root=self.root)

    def test_invalid_and_oversized_source_is_rejected(self):
        for text in ('', '\0', '\ud800', 'x'*16385):
            value=copy.deepcopy(self.reply);value['files']['fingerprint.py']=text
            with self.assertRaises(StateError): p.parse_builder(json.dumps(value).encode(),root=self.root)
        value=copy.deepcopy(self.reply);value['files']={k:'x'*13000 for k in p.FILES}
        with self.assertRaises(StateError): p.parse_builder(canonical(value),root=self.root)

    def test_duplicate_nested_keys_non_json_and_deep_inputs_rejected(self):
        duplicate=b'{"task_id":"a","task_id":"b"}'
        for raw in (duplicate,b'[]',b'{"a":NaN}',b'{"a":"\\ud800"}',b' '*32769,b'['*2000+b']'*2000):
            with self.subTest(raw=raw[:30]), self.assertRaises(StateError):
                p.parse_builder(raw,root=self.root)

    def test_untrusted_candidate_is_not_executed_or_authorized(self):
        value=p.parse_builder(self.raw,root=self.root)
        self.assertEqual(value['files'],self.reply['files'])
        self.assertFalse(value['executed']);self.assertFalse(value['gate_authority'])
        self.assertEqual(value['status'],'UNAUTHENTICATED_CANDIDATE')

    def test_two_reviewers_bind_same_candidate_but_distinct_role_and_provider(self):
        inspector=self.review('inspector');qa=self.review('qa')
        self.assertEqual(inspector['candidate_digest'],qa['candidate_digest'])
        self.assertNotEqual(inspector['packet_digest'],qa['packet_digest'])
        self.assertEqual((inspector['provider_family'],qa['provider_family']),('anthropic','google'))
        self.assertFalse(qa['candidate_commit_verified'])
        self.assertEqual(qa['model_id'],'gemini-3.8-flash')
        with self.assertRaises(StateError): self.review('builder')
        with self.assertRaises(StateError): self.review(commit='main')

    def test_changed_candidate_or_commit_changes_review_binding(self):
        value=copy.deepcopy(self.reply);value['files']['fingerprint.py']+='changed\n'
        self.assertNotEqual(self.review()['packet_digest'],self.review(raw=canonical(value))['packet_digest'])
        self.assertNotEqual(self.review()['packet_digest'],self.review(commit='b'*40)['packet_digest'])

    def test_review_rejects_cross_role_and_stale_candidate(self):
        with self.assertRaises(StateError): self.parse_review(self.assessment('inspector'))
        for name in p.REVIEW_BINDINGS:
            value=self.assessment();value[name]='wrong'
            with self.subTest(name=name),self.assertRaises(StateError):self.parse_review(value)

    def test_high_findings_require_rejection_and_paths_are_bounded(self):
        value=self.assessment();value['findings']=[{'severity':'high','path':'fingerprint.py','detail':'Race found'}]
        with self.assertRaises(StateError): self.parse_review(value)
        value['verdict']='REJECTED';result=self.parse_review(value)
        self.assertFalse(result['gate_authority']);self.assertFalse(result['tests_executed'])
        self.assertFalse(result['production_release_authorized'])
        value['findings'][0]['path']='../../secret'
        with self.assertRaises(StateError):self.parse_review(value)

    def test_unexpected_review_fields_and_unbounded_details_rejected(self):
        for change in ({'findings':[{}]}, {'findings':[{'severity':'low','path':'fingerprint.py','detail':'x'*1001}]},
                       {'rationale':' '}, {'rationale':'x'*2001}, {'tests_passed':True}):
            with self.subTest(change=change),self.assertRaises(StateError):self.parse_review({**self.assessment(),**change})


if __name__ == '__main__': unittest.main()
