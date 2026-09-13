variable "pilot_github_repository" {
  description = "Exact private GitHub repository used by the governed live pilot."
  type        = string
  default     = "timbrydges/tims-factory-pilot"

  validation {
    condition     = var.pilot_github_repository == "timbrydges/tims-factory-pilot"
    error_message = "Pilot runtime is bound to timbrydges/tims-factory-pilot."
  }
}

variable "pilot_github_repository_owner_id" {
  description = "Immutable GitHub account ID for the pilot repository owner."
  type        = string
  default     = "214414801"

  validation {
    condition     = var.pilot_github_repository_owner_id == "214414801"
    error_message = "Pilot runtime is bound to Tim Brydges' immutable GitHub owner ID."
  }
}

variable "pilot_github_repository_id" {
  description = "Immutable GitHub repository ID for timbrydges/tims-factory-pilot."
  type        = string
  default     = "1368587958"

  validation {
    condition     = var.pilot_github_repository_id == "1368587958"
    error_message = "Pilot runtime is bound to repository ID 1368587958."
  }
}

variable "pilot_github_environment" {
  description = "GitHub Environment bound into the pilot-runtime OIDC subject."
  type        = string
  default     = "production"

  validation {
    condition     = var.pilot_github_environment == "production"
    error_message = "Pilot runtime OIDC is bound to the production environment."
  }
}

locals {
  pilot_repository_parts = split("/", var.pilot_github_repository)
  pilot_repository_owner = local.pilot_repository_parts[0]
  pilot_repository_name  = local.pilot_repository_parts[1]
  pilot_oidc_subject     = "repo:${local.pilot_repository_owner}@${var.pilot_github_repository_owner_id}/${local.pilot_repository_name}@${var.pilot_github_repository_id}:environment:${var.pilot_github_environment}"

  pilot_runtime_role_name        = "tims-software-factory-pilot-runtime"
  pilot_bedrock_model_id         = "anthropic.claude-sonnet-5"
  pilot_bedrock_profile_id       = "us.anthropic.claude-sonnet-5"
  pilot_bedrock_profile_arn      = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${local.pilot_bedrock_profile_id}"
  pilot_bedrock_foundation_model = "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/${local.pilot_bedrock_model_id}"
}

data "aws_iam_policy_document" "pilot_runtime_trust" {
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
      values   = [local.pilot_oidc_subject]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner_id"
      values   = [var.pilot_github_repository_owner_id]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_id"
      values   = [var.pilot_github_repository_id]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:ref"
      values   = ["refs/heads/main"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:environment"
      values   = [var.pilot_github_environment]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:workflow"
      values   = ["pilot-live"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:actor_id"
      values   = [var.pilot_github_repository_owner_id]
    }
  }
}

resource "aws_iam_role" "github_pilot_runtime" {
  name                 = local.pilot_runtime_role_name
  assume_role_policy   = data.aws_iam_policy_document.pilot_runtime_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "github_pilot_runtime_state" {
  role       = aws_iam_role.github_pilot_runtime.name
  policy_arn = aws_iam_policy.controller_state.arn
}

data "aws_iam_policy_document" "pilot_runtime" {
  statement {
    sid     = "InvokeExactInspectorInferenceProfile"
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      local.pilot_bedrock_profile_arn,
    ]
  }

  statement {
    sid     = "InvokeInspectorModelOnlyThroughExactProfile"
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      local.pilot_bedrock_foundation_model,
    ]

    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.pilot_bedrock_profile_arn]
    }
  }

  statement {
    sid    = "PilotReleaseObjectsOnly"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.factory_releases.arn}/pilot-releases/*",
    ]
  }
}

resource "aws_iam_role_policy" "github_pilot_runtime" {
  role   = aws_iam_role.github_pilot_runtime.id
  policy = data.aws_iam_policy_document.pilot_runtime.json
}

output "pilot_repository_variables" {
  description = "Bind these non-secret values to timbrydges/tims-factory-pilot."
  value = {
    AWS_REGION                   = var.aws_region
    AWS_PILOT_RUNTIME_ROLE_ARN   = aws_iam_role.github_pilot_runtime.arn
    FACTORY_RELEASE_BUCKET       = aws_s3_bucket.factory_releases.id
    FACTORY_STATE_TABLE          = aws_dynamodb_table.factory_state.name
  }
}

output "pilot_runtime_oidc_subject" {
  value = local.pilot_oidc_subject
}

output "pilot_bedrock_inference_profile_arn" {
  value = local.pilot_bedrock_profile_arn
}
