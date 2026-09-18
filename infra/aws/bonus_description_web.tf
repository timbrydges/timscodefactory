# Production-only identity for the Bonus Library description endpoint.
# Role deployment does not activate the application or reset its budget.
locals {
  bonus_web_issuer  = "oidc.vercel.com/tim-brydges-projects"
  bonus_web_model   = "anthropic.claude-sonnet-4-5-20250929-v1:0"
  bonus_web_profile = "arn:aws:bedrock:ca-central-1:666730517561:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}

resource "aws_iam_openid_connect_provider" "bonus_web" {
  url            = "https://${local.bonus_web_issuer}"
  client_id_list = ["https://vercel.com/tim-brydges-projects"]
  tags           = { Project = "bonus-library", Purpose = "production-description" }
}

resource "aws_iam_role" "bonus_description_web" {
  name                 = "tims-software-factory-bonus-description-web"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = aws_iam_openid_connect_provider.bonus_web.arn }
      Condition = { StringEquals = {
        "${local.bonus_web_issuer}:aud" = "https://vercel.com/tim-brydges-projects"
        "${local.bonus_web_issuer}:sub" = "owner:tim-brydges-projects:project:bonus-library:environment:production"
      } }
    }]
  })
  tags = { Project = "bonus-library", Purpose = "production-description" }
}

resource "aws_iam_role_policy" "bonus_description_web" {
  name = "bounded-description"
  role = aws_iam_role.bonus_description_web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "bedrock:CountTokens",
      Resource = "arn:aws:bedrock:ca-central-1::foundation-model/${local.bonus_web_model}" },
      { Effect = "Allow", Action = "bedrock:InvokeModel", Resource = local.bonus_web_profile },
      { Effect   = "Allow", Action = "bedrock:InvokeModel",
        Resource = [for region in ["ca-central-1", "us-east-1", "us-east-2", "us-west-2"] : "arn:aws:bedrock:${region}::foundation-model/${local.bonus_web_model}"],
      Condition = { StringEquals = { "bedrock:InferenceProfileArn" = local.bonus_web_profile } } },
      { Effect   = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
        Resource = "arn:aws:dynamodb:ca-central-1:666730517561:table/tims-software-factory-state",
      Condition = { "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["BONUS_LIBRARY#DESCRIPTION_TEST#20260918"] } } }
    ]
  })
}

output "bonus_description_web_role_arn" {
  value = aws_iam_role.bonus_description_web.arn
}
