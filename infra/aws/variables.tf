variable "aws_region" {
  description = "AWS region for the state store and release bucket."
  type        = string
  default     = "ca-central-1"
}

variable "github_repository" {
  description = "Exact GitHub owner/repository binding."
  type        = string
  default     = "timbrydges/timscodefactory"

  validation {
    condition     = var.github_repository == "timbrydges/timscodefactory"
    error_message = "Pilot #1 is bound to timbrydges/timscodefactory."
  }
}

variable "github_repository_owner_id" {
  description = "Immutable GitHub user or organization ID for the repository owner."
  type        = string
  default     = "214414801"

  validation {
    condition     = var.github_repository_owner_id == "214414801"
    error_message = "Pilot #1 is bound to Tim Brydges' immutable GitHub owner ID."
  }
}

variable "github_repository_id" {
  description = "Immutable GitHub repository ID used in post-July-2026 OIDC subjects."
  type        = string
  default     = "1345656137"

  validation {
    condition     = var.github_repository_id == "1345656137"
    error_message = "Pilot #1 is bound to timbrydges/timscodefactory repository ID 1345656137."
  }
}

variable "github_environment" {
  description = "Protected GitHub Environment bound into the OIDC subject."
  type        = string
  default     = "production"

  validation {
    condition     = var.github_environment == "production"
    error_message = "Pilot #1 releases are bound to the production environment."
  }
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing GitHub Actions OIDC provider ARN. Leave null to create it in this account."
  type        = string
  default     = null

  validation {
    condition = var.existing_github_oidc_provider_arn == null || can(regex(
      "^arn:[a-z0-9-]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$",
      var.existing_github_oidc_provider_arn
    ))
    error_message = "The existing provider ARN must identify token.actions.githubusercontent.com in this AWS account."
  }
}
