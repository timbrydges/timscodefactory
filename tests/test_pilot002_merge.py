import copy
import unittest
from unittest.mock import patch

from factory_runtime import pilot002_repository as p
from factory_state.model import StateError


class MergeObservationTests(unittest.TestCase):
    def setUp(self):
        self.candidate={'repository':'owner/repo','branch':'factory/task',
            'candidate_tree':'a'*40,'candidate_commit':'b'*40,'baseline_commit':'c'*40,
            'gate_authority':False,'production_release_authorized':False,'candidate_executed':False}
        self.pr={'number':3,'merged':True,'state':'closed','merge_commit_sha':'d'*40,
            'head':{'sha':'b'*40,'ref':'factory/task','repo':{'full_name':'owner/repo'}},
            'base':{'ref':'main','repo':{'full_name':'owner/repo'}}}
        self.merge={'sha':'d'*40,'tree':{'sha':'a'*40},'parents':[{'sha':'c'*40},{'sha':'b'*40}]}
        self.main={'ref':'refs/heads/main','object':{'type':'commit','sha':'d'*40}}

    def verify(self, observations=None, **overrides):
        args={'builder_response':b'fixture','candidate_commit':'b'*40,
              'merge_commit':'d'*40,'pull_request':3}
        args.update(overrides)
        with patch.object(p,'verify_published_candidate',return_value=self.candidate) as prior:
            with patch('subprocess.run') as process:
                read=unittest.mock.Mock(side_effect=observations or [self.pr,self.merge,self.main])
                result=p.verify_merged_candidate(None,None,github_read=read,**args)
                process.assert_not_called()
        prior.assert_called_once()
        self.assertEqual([c.args[0] for c in read.call_args_list],[
            'repos/owner/repo/pulls/3','repos/owner/repo/git/commits/'+'d'*40,
            'repos/owner/repo/git/ref/heads/main'])
        return result

    def test_exact_merge_observed_without_authority(self):
        result=self.verify()
        self.assertEqual(result['status'],'MERGED_CANDIDATE_BINDING_OBSERVED')
        for key in ('gate_authority','production_release_authorized','candidate_executed',
                    'owner_authorization_verified','factory_state_advanced'):
            self.assertIs(result[key],False)

    def test_drift_wrong_repository_and_malformed_observations_rejected(self):
        cases=[(0,['merged'],False),(0,['head','sha'],'e'*40),
            (0,['head','repo','full_name'],'attacker/repo'),(0,['base','ref'],'other'),
            (0,['number'],True),(0,['merge_commit_sha'],'e'*40),
            (1,['tree','sha'],'e'*40),(1,['parents'],[{'sha':'b'*40}]),
            (1,['parents'],[None]),(2,['object','sha'],'e'*40)]
        for index,path,value in cases:
            observations=copy.deepcopy([self.pr,self.merge,self.main]);target=observations[index]
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(StateError):self.verify(observations)
        for index in range(3):
            for value in (None,[],{}):
                observations=copy.deepcopy([self.pr,self.merge,self.main]);observations[index]=value
                with self.assertRaises(StateError):self.verify(observations)

    def test_invalid_identifiers_rejected_before_reads(self):
        for args in ({'pull_request':True},{'pull_request':0},{'merge_commit':'HEAD'}):
            with self.assertRaises(StateError):self.verify(**args)
