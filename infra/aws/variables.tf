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

variable "github_environment" {
  description = "Protected GitHub Environment bound into the OIDC subject."
  type        = string
  default     = "production"
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing GitHub Actions OIDC provider ARN. Leave null to create it in this account."
  type        = string
  default     = null
}

