data "aws_iam_policy_document" "owner_receipt_writer" {
  statement {
    sid       = "WriteOwnerReceiptOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.factory_releases.arn}/factory-scope-receipts/*/owner.json",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }
}

data "aws_iam_policy_document" "reviewer_receipt_writer" {
  statement {
    sid       = "WriteReviewerReceiptOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.factory_releases.arn}/factory-scope-receipts/*/reviewer.json",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }
}

resource "aws_iam_policy" "owner_receipt_writer" {
  name   = "${local.name_prefix}-owner-receipt-writer"
  policy = data.aws_iam_policy_document.owner_receipt_writer.json
}

resource "aws_iam_policy" "reviewer_receipt_writer" {
  name   = "${local.name_prefix}-reviewer-receipt-writer"
  policy = data.aws_iam_policy_document.reviewer_receipt_writer.json
}
