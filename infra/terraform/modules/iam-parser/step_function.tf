# step_function.tf - Step Function resources only

# Step Function IAM Role
resource "aws_iam_role" "step_function_role" {
  count = var.create_step_function ? 1 : 0
  name  = "${local.name_prefix}-stepfunction-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Step Function permissions to invoke all Lambda functions
resource "aws_iam_role_policy" "step_function_lambda_policy" {
  count = var.create_step_function && var.create_lambda ? 1 : 0
  name  = "${local.name_prefix}-stepfunction-lambda"
  role  = aws_iam_role.step_function_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          for func_arn in values(aws_lambda_function.iam_analyzer_functions) : func_arn.arn
        ]
      }
    ]
  })
}

# Step Function logging permissions
resource "aws_iam_role_policy" "step_function_logging_policy" {
  count = var.create_step_function ? 1 : 0
  name  = "${local.name_prefix}-stepfunction-logs"
  role  = aws_iam_role.step_function_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for Step Function
resource "aws_cloudwatch_log_group" "step_function_logs" {
  count             = var.create_step_function ? 1 : 0
  name              = "/aws/stepfunctions/${local.name_prefix}-iam-analyzer"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# Local values for function ARNs
locals {
  function_arns = var.create_lambda ? {
    read_s3              = aws_lambda_function.iam_analyzer_functions["read-s3"].arn
    start_cloudtrail     = aws_lambda_function.iam_analyzer_functions["start-cloudtrail"].arn
    check_cloudtrail     = aws_lambda_function.iam_analyzer_functions["check-cloudtrail"].arn
    fetch_terraform      = aws_lambda_function.iam_analyzer_functions["fetch-terraform"].arn
    parse_policies       = aws_lambda_function.iam_analyzer_functions["parse-policies"].arn
    apply_modifications  = aws_lambda_function.iam_analyzer_functions["apply-modifications"].arn
    github_pr            = aws_lambda_function.iam_analyzer_functions["github-pr"].arn
  } : {}
}

# Step Function State Machine - FIXED with no problematic Parameters
resource "aws_sfn_state_machine" "iam_analyzer" {
  count    = var.create_step_function && var.create_lambda ? 1 : 0
  name     = "${local.name_prefix}-iam-analyzer"
  role_arn = aws_iam_role.step_function_role[0].arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_function_logs[0].arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  definition = jsonencode({
    Comment = "IAM Least Privilege Analysis Workflow with Multiple Lambda Functions"
    StartAt = "ReadS3Data"
    States = {
      
      # Step 1: Read IAM data from S3 (dedicated function)
      ReadS3Data = {
        Type     = "Task"
        Resource = local.function_arns.read_s3
        Next     = "CheckUsersExist"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Check if we have users to analyze
      CheckUsersExist = {
        Type = "Choice"
        Choices = [
          {
            Variable      = "$.users[0]"
            IsPresent     = true
            Next         = "StartCloudTrailQuery"
          }
        ]
        Default = "NoUsersFound"
      }

      # Step 2: Start CloudTrail Lake query (dedicated function)
      StartCloudTrailQuery = {
        Type     = "Task"
        Resource = local.function_arns.start_cloudtrail
        Next     = "WaitForQuery"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Wait for CloudTrail query to complete
      WaitForQuery = {
        Type    = "Wait"
        Seconds = 30
        Next    = "CheckQueryStatus"
      }

      # Step 3: Check query status (dedicated function)
      CheckQueryStatus = {
        Type     = "Task"
        Resource = local.function_arns.check_cloudtrail
        Next     = "EvaluateQueryStatus"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Evaluate if query is done or needs more time
      EvaluateQueryStatus = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.query_status"
            StringEquals = "FINISHED"
            Next = "FetchTerraformFiles"
          },
          {
            Variable = "$.query_status"
            StringEquals = "FAILED"
            Next = "HandleError"
          }
        ]
        Default = "WaitLongerForQuery"
      }

      # Wait longer if query still running
      WaitLongerForQuery = {
        Type = "Wait"
        Seconds = 60
        Next = "CheckQueryStatus"
      }

      # Step 4: Fetch Terraform files (dedicated function)
      FetchTerraformFiles = {
        Type     = "Task"
        Resource = local.function_arns.fetch_terraform
        Next     = "ParseTerraformPolicies"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Step 5: Parse Terraform policies (dedicated function)
      ParseTerraformPolicies = {
        Type     = "Task"
        Resource = local.function_arns.parse_policies
        Next     = "ApplyModifications"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Step 6: Apply modifications to Terraform files
      ApplyModifications = {
        Type     = "Task"
        Resource = local.function_arns.apply_modifications
        Next     = "CheckModifications"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
          }
        ]
      }

      # Check if we have modifications to create a PR for
      CheckModifications = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.modifications_applied"
            BooleanEquals = true
            Next = "GenerateGitHubPR"
          }
        ]
        Default = "NoModificationsFound"
      }

      # Step 7: Generate GitHub PR (dedicated function)
      GenerateGitHubPR = {
        Type     = "Task"
        Resource = local.function_arns.github_pr
        Next     = "AnalysisAndPRCompleted"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "AnalysisCompletedNoPR"
            ResultPath  = "$.pr_error"
          }
        ]
      }

      # No modifications found
      NoModificationsFound = {
        Type = "Pass"
        Result = {
          message = "IAM analysis completed - no safe modifications to apply"
          workflow_status = "complete_no_modifications"
        }
        End = true
      }

      # Analysis completed with PR created
      AnalysisAndPRCompleted = {
        Type = "Pass"
        Result = {
          message = "IAM analysis completed and GitHub PR created successfully"
          workflow_status = "complete_with_pr"
        }
        End = true
      }

      # Analysis completed but PR failed
      AnalysisCompletedNoPR = {
        Type = "Pass"
        Result = {
          message = "IAM analysis completed but PR generation failed"
          workflow_status = "complete_no_pr"
        }
        End = true
      }

      # Handle case where no users found
      NoUsersFound = {
        Type = "Pass"
        Result = {
          statusCode = 200
          message    = "No users found to analyze"
          workflow_status = "no_users"
        }
        End = true
      }

      # Error handling state
      HandleError = {
        Type = "Fail"
        Cause = "An error occurred during IAM analysis"
      }
    }
  })
  
  tags = local.common_tags
}

# EventBridge rule to trigger Step Function (optional)
resource "aws_cloudwatch_event_rule" "daily_analysis" {
  count               = var.create_step_function && var.enable_daily_schedule ? 1 : 0
  name                = "${local.name_prefix}-iam-analyzer-daily"
  description         = "Trigger IAM analysis daily"
  schedule_expression = var.schedule_expression

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "step_function_target" {
  count     = var.create_step_function && var.enable_daily_schedule ? 1 : 0
  rule      = aws_cloudwatch_event_rule.daily_analysis[0].name
  target_id = "IAMAnalyzerStepFunction"
  arn       = aws_sfn_state_machine.iam_analyzer[0].arn
  role_arn  = aws_iam_role.eventbridge_role[0].arn
}

# EventBridge IAM role
resource "aws_iam_role" "eventbridge_role" {
  count = var.create_step_function && var.enable_daily_schedule ? 1 : 0
  name  = "${local.name_prefix}-iam-analyzer-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "eventbridge_step_function_policy" {
  count = var.create_step_function && var.enable_daily_schedule ? 1 : 0
  name  = "${local.name_prefix}-iam-analyzer-eventbridge-stepfunction"
  role  = aws_iam_role.eventbridge_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "states:StartExecution"
        ]
        Resource = aws_sfn_state_machine.iam_analyzer[0].arn
      }
    ]
  })
}