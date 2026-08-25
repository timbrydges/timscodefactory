data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name_prefix = "tims-software-factory"
  oidc_subject = "repo:${var.github_repository}:environment:${var.github_environment}"
  oidc_provider_arn = var.existing_github_oidc_provider_arn != null ? var.existing_github_oidc_provider_arn : aws_iam_openid_connect_provider.github[0].arn
}

resource "aws_dynamodb_table" "factory_state" {
  name         = "${local.name_prefix}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

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

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  deletion_protection_enabled = true
}

resource "aws_s3_bucket" "factory_releases" {
  bucket = "${local.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket_versioning" "factory_releases" {
  bucket = aws_s3_bucket.factory_releases.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "factory_releases" {
  bucket = aws_s3_bucket.factory_releases.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "factory_releases" {
  bucket                  = aws_s3_bucket.factory_releases.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.existing_github_oidc_provider_arn == null ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "release_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.oidc_subject]
    }
  }
}

resource "aws_iam_role" "github_release" {
  name                 = "${local.name_prefix}-github-release"
  assume_role_policy   = data.aws_iam_policy_document.release_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "release" {
  statement {
    sid     = "WriteImmutableReleaseObjects"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "${aws_s3_bucket.factory_releases.arn}/releases/*"
    ]
  }

  statement {
    sid       = "RecordDeployment"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.factory_state.arn]

    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["FACTORY#tims-software-factory#DEPLOYMENT"]
    }
  }
}

resource "aws_iam_role_policy" "github_release" {
  role   = aws_iam_role.github_release.id
  policy = data.aws_iam_policy_document.release.json
}

data "aws_iam_policy_document" "controller_state" {
  statement {
    sid    = "ControllerAuthoritativeState"
    effect = "Allow"
    actions = [
      "dynamodb:ConditionCheckItem",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:TransactWriteItems",
      "dynamodb:UpdateItem"
    ]
    resources = [
      aws_dynamodb_table.factory_state.arn,
      "${aws_dynamodb_table.factory_state.arn}/index/*"
    ]
  }
}

resource "aws_iam_policy" "controller_state" {
  name   = "${local.name_prefix}-controller-state"
  policy = data.aws_iam_policy_document.controller_state.json
}
