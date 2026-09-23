from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReceiptWriterIAMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "infra/aws/receipt_writer.tf").read_text(encoding="utf-8")

    def test_owner_and_reviewer_writers_are_separate_exact_suffix_policies(self):
        self.assertIn('data "aws_iam_policy_document" "owner_receipt_writer"', self.text)
        self.assertIn('data "aws_iam_policy_document" "reviewer_receipt_writer"', self.text)
        self.assertIn('/factory-scope-receipts/*/owner.json"', self.text)
        self.assertIn('/factory-scope-receipts/*/reviewer.json"', self.text)

    def test_writers_can_only_put_encrypted_objects(self):
        self.assertEqual(self.text.count('actions   = ["s3:PutObject"]'), 2)
        self.assertEqual(self.text.count('variable = "s3:x-amz-server-side-encryption"'), 2)
        self.assertEqual(self.text.count('values   = ["AES256"]'), 2)
        for prohibited in (
            "s3:GetObject",
            "s3:ListBucket",
            "s3:DeleteObject",
            "s3:PutObjectAcl",
            'resources = ["*"]',
        ):
            self.assertNotIn(prohibited, self.text)

    def test_policies_are_prepared_but_not_attached(self):
        self.assertNotIn("aws_iam_role_policy_attachment", self.text)
        self.assertNotIn("aws_iam_user_policy_attachment", self.text)


if __name__ == "__main__":
    unittest.main()
