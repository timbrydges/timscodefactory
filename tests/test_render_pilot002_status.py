import unittest
from render_pilot002_status import render,money


class StatusPageTests(unittest.TestCase):
    def report(self):
        return {'execution_authorized':False,'gate_authority':False,'task':{'state':'PAUSED','version':0},
            'workers':{'<script>alert(1)</script>':{'status':'UNKNOWN','disabled_observed':False}},
            'attempts':{'qa':{'status':'STARTED','reserved_micro_usd':250000,'reported_actual_micro_usd':None}},
            'known_reserved_micro_usd':250000,'reservation_total_complete':False,
            'finished_at':'2026-10-06T01:01:38Z','status':'INCOMPLETE','scope':'Pilot only','unavailable':['worker:qa']}

    def test_untrusted_text_escaped_and_unknowns_not_claimed_safe(self):
        page=render(self.report())
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn('Not confirmed disabled',page)
        self.assertIn('US$0.250000 (incomplete)',page)
        self.assertIn('Not recorded',page)
        self.assertIn("default-src 'none'",page)
        self.assertIn('Snapshot only',page)

    def test_execution_authority_and_invalid_money_rejected(self):
        report=self.report();report['gate_authority']=True
        with self.assertRaises(ValueError):render(report)
        for value in (True,-1,0.25,'250000'):
            with self.assertRaises(ValueError):money(value)
