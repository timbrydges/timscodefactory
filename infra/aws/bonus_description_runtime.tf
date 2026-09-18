# Separate test role; identity-canary remains powerless. Generation stays disabled.
locals {
  bonus_description_profile = "arn:aws:bedrock:ca-central-1:666730517561:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"
  bonus_description_model   = "anthropic.claude-sonnet-4-5-20250929-v1:0"
  bonus_description_ledger  = "BONUS_LIBRARY#DESCRIPTION_TEST#20260918"
}

resource "aws_iam_role" "description_test" {
  name                 = "tims-software-factory-bonus-library-description-test"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = "arn:aws:iam::666730517561:oidc-provider/token.actions.githubusercontent.com"
      }
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud"                 = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub"                 = "repo:timbrydges@214414801/bonus-library@1375052827:environment:production"
        "token.actions.githubusercontent.com:repository_owner_id" = "214414801"
        "token.actions.githubusercontent.com:repository_id"       = "1375052827"
        "token.actions.githubusercontent.com:ref"                 = "refs/heads/main"
        "token.actions.githubusercontent.com:environment"         = "production"
        "token.actions.githubusercontent.com:workflow"            = "bonus-library-description-test"
        "token.actions.githubusercontent.com:actor_id"            = "214414801"
      } }
    }]
  })
  tags = { Project = "bonus-library", Purpose = "bounded-description-test" }
}

resource "aws_iam_role_policy" "description_test" {
  role = aws_iam_role.description_test.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "bedrock:CountTokens",
      Resource = "arn:aws:bedrock:ca-central-1::foundation-model/${local.bonus_description_model}" },
      { Effect = "Allow", Action = "bedrock:InvokeModel", Resource = local.bonus_description_profile },
      { Effect   = "Allow", Action = "bedrock:InvokeModel",
        Resource = [for region in ["ca-central-1", "us-east-1", "us-east-2", "us-west-2"] : "arn:aws:bedrock:${region}::foundation-model/${local.bonus_description_model}"],
      Condition = { StringEquals = { "bedrock:InferenceProfileArn" = local.bonus_description_profile } } },
      { Effect   = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:TransactWriteItems"],
        Resource = "arn:aws:dynamodb:ca-central-1:666730517561:table/tims-software-factory-state",
      Condition = { "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = [local.bonus_description_ledger] } } }
    ]
  })
}

output "description_test_role_arn" {
  value = aws_iam_role.description_test.arn
}
