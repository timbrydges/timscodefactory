from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare_pilot002_builder_qualification as p


class QualificationProposalTests(unittest.TestCase):
    def setUp(self):
        self.observation=json.loads((p.ROOT/'factory/evidence/pilot-002-builder-token-verified.json').read_text())
        self.review=json.loads((p.ROOT/'factory/evidence/pilot-002-builder-price-review.json').read_text())
        self.now=datetime(2026,10,3,22,31,tzinfo=timezone.utc)

    def propose(self,observation=None,review=None,now=None):
        return p.propose(p.ROOT,observation or self.observation,review or self.review,'a'*40,now or self.now)

    def test_real_evidence_proposes_conservative_bound_without_activation(self):
        with patch('boto3.Session') as session:
            result=self.propose();session.assert_not_called()
        self.assertEqual(result['pricing']['maximum_cost_micro_usd'],212992)
        self.assertEqual(result['reserved_micro_usd'],250000);self.assertFalse(result['live_execution_authorized'])
        self.assertEqual(result['qualification']['input_token_bound'],32768)

    def test_substituted_request_or_unsuccessful_count_is_rejected(self):
        for key,value in [('http_requests',2),('http_status',401),('generation_requests',1),
                          ('generation_request_digest','sha256:'+'a'*64),('input_tokens',True),('input_tokens',32769)]:
            with self.assertRaises(ValueError):self.propose(observation={**self.observation,key:value})

    def test_rates_caps_and_claimed_generation_access_cannot_change(self):
        for key,value in [('input_micro_usd_per_million',5000000),('output_token_bound',8192),
                          ('maximum_cost_micro_usd',250001),('model_generation_access_proven',True)]:
            with self.assertRaises(ValueError):self.propose(review={**self.review,key:value})

    def test_expiry_cannot_be_refreshed_by_regenerating_proposal(self):
        first=self.propose();later=self.propose(now=self.now+timedelta(hours=2))
        self.assertEqual(first['qualification']['expires_at'],later['qualification']['expires_at'])
        with self.assertRaises(ValueError):self.propose(now=self.now+timedelta(days=1))
        with self.assertRaises(ValueError):self.propose(now=self.now-timedelta(hours=1))


if __name__=='__main__':unittest.main()
