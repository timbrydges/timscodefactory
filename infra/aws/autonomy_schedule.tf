variable "deploy_disabled_autonomy_schedule" {
  description = "Create the acceptance scheduler in DISABLED state only."
  type        = bool
  default     = false
}

locals {
  autonomy_schedule_name = "tims-software-factory-autonomy-acceptance"
  autonomy_target_arn     = "arn:${data.aws_partition.current.partition}:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:tims-software-factory-autonomy-controller:acceptance"
  autonomy_schedule_arn   = "arn:${data.aws_partition.current.partition}:scheduler:${var.aws_region}:${data.aws_caller_identity.current.account_id}:schedule/default/${local.autonomy_schedule_name}"
}

data "aws_iam_policy_document" "autonomy_scheduler_trust" {
  count = var.deploy_disabled_autonomy_schedule ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.autonomy_schedule_arn]
    }
  }
}

resource "aws_iam_role" "autonomy_scheduler" {
  count                = var.deploy_disabled_autonomy_schedule ? 1 : 0
  name                 = "${local.name_prefix}-autonomy-scheduler"
  assume_role_policy   = data.aws_iam_policy_document.autonomy_scheduler_trust[0].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "autonomy_scheduler_invoke" {
  count = var.deploy_disabled_autonomy_schedule ? 1 : 0

  statement {
    sid       = "InvokeExactAcceptanceControllerAlias"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [local.autonomy_target_arn]
  }
}

resource "aws_iam_role_policy" "autonomy_scheduler_invoke" {
  count  = var.deploy_disabled_autonomy_schedule ? 1 : 0
  role   = aws_iam_role.autonomy_scheduler[0].id
  policy = data.aws_iam_policy_document.autonomy_scheduler_invoke[0].json
}

resource "aws_scheduler_schedule" "autonomy_acceptance" {
  count = var.deploy_disabled_autonomy_schedule ? 1 : 0

  name                         = local.autonomy_schedule_name
  state                        = "DISABLED"
  schedule_expression          = "rate(15 minutes)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = local.autonomy_target_arn
    role_arn = aws_iam_role.autonomy_scheduler[0].arn
    input = jsonencode({
      factory_id = "factory"
      task_id    = "deterministic-text-fingerprint"
      mode       = "acceptance"
    })

    retry_policy {
      maximum_event_age_in_seconds = 60
      maximum_retry_attempts       = 0
    }
  }
}
