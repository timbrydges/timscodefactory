import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import receipt_writer_live_canary as canary


class ReceiptWriterLiveCanaryTests(unittest.TestCase):
    def test_each_identity_writes_only_inert_own_object_and_checks_denials(self):
        for kind, role in canary.ROLES.items():
            with self.subTest(kind=kind):
                calls = []

                def aws(service, action, *args, expect_denied=False):
                    if action == 'get-caller-identity':
                        return {'Account': canary.ACCOUNT,
                                'Arn': f'arn:aws:sts::{canary.ACCOUNT}:assumed-role/{role}/run'}
                    calls.append((args, expect_denied))
                    body = Path(args[args.index('--body') + 1]).read_text()
                    self.assertEqual(json.loads(body)['kind'], 'receipt_iam_canary_not_approval')
                    return None if expect_denied else {'VersionId': 'version-1',
                                                        'ServerSideEncryption': 'AES256'}

                with patch.object(canary, 'aws', side_effect=aws):
                    result = canary.canary(kind, '123-1', 'a' * 40)
                self.assertEqual([denied for _, denied in calls], [False, True, True])
                self.assertEqual(result['approval_receipts_published'], 0)
                self.assertTrue(result['object_key'].endswith(f'/{kind}.json'))

    def test_wrong_identity_fails_before_object_write(self):
        with patch.object(canary, 'aws', return_value={'Account': canary.ACCOUNT,
                'Arn': f'arn:aws:sts::{canary.ACCOUNT}:assumed-role/other/run'}) as aws:
            with self.assertRaisesRegex(RuntimeError, 'unexpected identity'):
                canary.canary('owner', '123-1', 'a' * 40)
        self.assertEqual(aws.call_count, 1)


if __name__ == '__main__':
    unittest.main()
