# Prepared only. Attach to a separately reviewed broker runtime identity.
resource "aws_dynamodb_table" "acceptance_broker_claims" {
  name                        = "tims-factory-acceptance-broker-claims"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "PK"
  range_key                   = "SK"
  deletion_protection_enabled = true

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  # No TTL: deletion could reopen a dispatch after an unknown provider outcome.
}

data "aws_iam_policy_document" "acceptance_broker_records" {
  statement {
    sid       = "ReadExactAcceptanceReservations"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.acceptance_budget.arn]

    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["ACTIVATION#*"]
    }
  }

  statement {
    sid       = "ClaimExactAcceptanceDispatch"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.acceptance_broker_claims.arn]

    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["ACTIVATION#*"]
    }
  }
}

resource "aws_iam_policy" "acceptance_broker_records" {
  name   = "${local.name_prefix}-acceptance-broker-records"
  policy = data.aws_iam_policy_document.acceptance_broker_records.json
}
