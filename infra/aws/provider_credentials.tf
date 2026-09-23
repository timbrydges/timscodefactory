locals {
  provider_openai_secret_name = "tims-software-factory/provider/openai/acceptance"
}

resource "aws_kms_key" "provider_credentials" {
  description             = "Encrypt the Factory provider-broker credential only."
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "provider_credentials" {
  name          = "alias/tims-software-factory-provider-credentials"
  target_key_id = aws_kms_key.provider_credentials.key_id
}

resource "aws_secretsmanager_secret" "provider_openai" {
  name                    = local.provider_openai_secret_name
  description             = "OpenAI key readable only by the isolated Factory provider broker."
  kms_key_id              = aws_kms_key.provider_credentials.arn
  recovery_window_in_days = 30
}

data "aws_iam_policy_document" "provider_broker_secret_reader" {
  statement {
    sid       = "ReadExactCurrentProviderSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.provider_openai.arn]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "secretsmanager:VersionStage"
      values   = ["AWSCURRENT"]
    }
  }

  statement {
    sid       = "DecryptOnlyThroughExactSecretsManagerRegion"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.provider_credentials.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "provider_broker_secret_reader" {
  name   = "${local.name_prefix}-provider-broker-secret-reader"
  policy = data.aws_iam_policy_document.provider_broker_secret_reader.json
}
