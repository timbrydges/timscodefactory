output "github_repository_variables" {
  description = "Bind these exact non-secret outputs as GitHub repository variables."
  value = {
    AWS_REGION             = var.aws_region
    AWS_RELEASE_ROLE_ARN   = aws_iam_role.github_release.arn
    FACTORY_RELEASE_BUCKET = aws_s3_bucket.factory_releases.id
    FACTORY_STATE_TABLE    = aws_dynamodb_table.factory_state.name
  }
}

output "controller_state_policy_arn" {
  description = "Attach to the controller workload identity only."
  value       = aws_iam_policy.controller_state.arn
}

output "release_oidc_subject" {
  value = local.oidc_subject
}

