locals {
  bonus_library_repository          = "timbrydges/bonus-library"
  bonus_library_repository_owner_id = "214414801"
  bonus_library_repository_id       = "1375052827"
  bonus_library_environment         = "production"
  bonus_library_workflow            = "bonus-library-identity-canary"
  bonus_library_oidc_subject        = "repo:timbrydges@${local.bonus_library_repository_owner_id}/bonus-library@${local.bonus_library_repository_id}:environment:${local.bonus_library_environment}"
}

data "aws_iam_policy_document" "bonus_library_identity_trust" {
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
      values   = [local.bonus_library_oidc_subject]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner_id"
      values   = [local.bonus_library_repository_owner_id]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_id"
      values   = [local.bonus_library_repository_id]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:ref"
      values   = ["refs/heads/main"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:environment"
      values   = [local.bonus_library_environment]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:workflow"
      values   = [local.bonus_library_workflow]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:actor_id"
      values   = [local.bonus_library_repository_owner_id]
    }
  }
}

resource "aws_iam_role" "github_bonus_library_identity" {
  name                 = "tims-software-factory-bonus-library-identity"
  assume_role_policy   = data.aws_iam_policy_document.bonus_library_identity_trust.json
  max_session_duration = 3600

  tags = {
    Project    = "bonus-library"
    Repository = local.bonus_library_repository
    Purpose    = "identity-canary-only"
  }
}

# Deliberately no identity policy or policy attachment. This role proves the
# immutable GitHub OIDC binding only and grants no project runtime capability.

output "bonus_library_identity" {
  description = "Non-secret values for the Bonus Library identity canary."
  value = {
    AWS_REGION                      = var.aws_region
    AWS_PROJECT_IDENTITY_ROLE_ARN   = aws_iam_role.github_bonus_library_identity.arn
    BONUS_LIBRARY_OIDC_SUBJECT      = local.bonus_library_oidc_subject
    BONUS_LIBRARY_REPOSITORY_ID     = local.bonus_library_repository_id
    BONUS_LIBRARY_REPOSITORY_OWNER  = local.bonus_library_repository_owner_id
  }
}
