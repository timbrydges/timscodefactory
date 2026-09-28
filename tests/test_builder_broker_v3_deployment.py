import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_builder_broker_v3 as deploy


def change(name, property_name, source, evaluation, cause):
    return {'ResourceChange': {'LogicalResourceId': name, 'Action': 'Modify',
        'Replacement': 'False', 'Scope': ['Properties'], 'Details': [{
            'Target': {'Attribute': 'Properties', 'Name': property_name,
                       'RequiresRecreation': 'Never'},
            'ChangeSource': source, 'Evaluation': evaluation,
            'CausingEntity': cause}]}}


class BuilderBrokerPinTests(unittest.TestCase):
    def test_template_pin_matches_verified_broker_version(self):
        template = deploy._template()
        statements = template['Resources']['BuilderRole']['Properties']['Policies'][1][
            'Fn::If'][1]['PolicyDocument']['Statement']
        self.assertEqual([x['Resource'] for x in statements if x.get('Sid') ==
                          'InvokePinnedCredentialFreeBroker'], [deploy.BROKER])

    def test_only_exact_in_place_role_and_dependency_changes_pass(self):
        changes = [change('BuilderRole', 'Policies', 'DirectModification', 'Static', None),
                   change('BuilderFunction', 'Role', 'ResourceAttribute', 'Dynamic',
                          'BuilderRole.Arn')]
        deploy.validate_changes(changes)
        changes[0]['ResourceChange']['Details'][0]['Target']['Name'] = 'AssumeRolePolicyDocument'
        with self.assertRaisesRegex(RuntimeError, 'unexpected dependency'):
            deploy.validate_changes(changes)

    def test_deployed_template_must_differ_only_by_old_broker_pin(self):
        proposed = deploy._template()
        old = json.loads(json.dumps(proposed))
        statements = old['Resources']['BuilderRole']['Properties']['Policies'][1][
            'Fn::If'][1]['PolicyDocument']['Statement']
        for statement in statements:
            if statement.get('Sid') == 'InvokePinnedCredentialFreeBroker':
                statement['Resource'] = deploy.OLD_BROKER
        with patch.object(deploy, 'aws', return_value={'TemplateBody': old}):
            deploy._old_template_matches(proposed)
        old['Resources']['BuilderFunction']['Properties']['Timeout'] += 1
        with patch.object(deploy, 'aws', return_value={'TemplateBody': old}):
            with self.assertRaisesRegex(RuntimeError, 'differs beyond'):
                deploy._old_template_matches(proposed)


if __name__ == '__main__':
    unittest.main()
