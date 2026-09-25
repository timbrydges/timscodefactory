# Prepared only. The Builder policy is deliberately unattached until the
# isolated operational backend deployment is reviewed and canaried.
resource "aws_dynamodb_table" "acceptance_budget" {
  name                        = "tims-factory-acceptance-budget"
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

  # No TTL: deleting reservation history could reopen an activation budget.
}

data "aws_iam_policy_document" "acceptance_budget_builder" {
  statement {
    sid       = "ReserveAndReconcileAcceptanceAttempts"
    effect    = "Allow"
    actions   = ["dynamodb:TransactWriteItems", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.acceptance_budget.arn]

    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["ACTIVATION#*"]
    }
  }
}

resource "aws_iam_policy" "acceptance_budget_builder" {
  name   = "${local.name_prefix}-acceptance-budget-builder"
  policy = data.aws_iam_policy_document.acceptance_budget_builder.json
}
