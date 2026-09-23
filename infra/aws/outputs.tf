output "github_repository_variables" {
  description = "Bind these exact non-secret outputs as GitHub repository variables."
  value = {
    AWS_REGION              = var.aws_region
    AWS_RELEASE_ROLE_ARN    = aws_iam_role.github_release.arn
    AWS_CONTROLLER_ROLE_ARN = aws_iam_role.github_controller.arn
    FACTORY_RELEASE_BUCKET  = aws_s3_bucket.factory_releases.id
    FACTORY_STATE_TABLE     = aws_dynamodb_table.factory_state.name
  }
}

output "controller_state_policy_arn" {
  description = "Attached only to the controller workload identity."
  value       = aws_iam_policy.controller_state.arn
}

output "release_oidc_subject" {
  value = local.oidc_subject
}

output "controller_role_arn" {
  value = aws_iam_role.github_controller.arn
}

output "provider_openai_secret_arn" {
  description = "Exact secret ARN to bind into the isolated provider broker deployment."
  value       = aws_secretsmanager_secret.provider_openai.arn
}

output "provider_broker_secret_reader_policy_arn" {
  description = "Attach only to the future isolated provider-broker runtime role."
  value       = aws_iam_policy.provider_broker_secret_reader.arn
}
