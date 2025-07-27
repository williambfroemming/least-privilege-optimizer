# step_function.tf - Step Function with PR Generation

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

# Step Function permissions to invoke your existing Lambda
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
          aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn,
          "${aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn}:*"
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

# Step Function State Machine with PR Generation
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
    Comment = "IAM Least Privilege Analysis Workflow with PR Generation"
    StartAt = "ReadS3Data"
    States = {
      
      # Step 1: Read IAM data from S3
      ReadS3Data = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "read_s3_data",
          "input.$": "$"
        }
        Next       = "CheckUsersExist"
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

      # Step 2: Start CloudTrail Lake query
      StartCloudTrailQuery = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "start_cloudtrail_query",
          "users.$": "$.users",
          "metadata.$": "$.metadata",
          "iam_data.$": "$.iam_data",
          "roles.$": "$.roles"
        }
        Next       = "WaitForQuery"
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

      # Step 3: Check query status and get results
      CheckQueryStatus = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "check_cloudtrail_query",
          "query_id.$": "$.query_id",
          "users.$": "$.users",
          "metadata.$": "$.metadata",
          "iam_data.$": "$.iam_data",
          "roles.$": "$.roles",
          "query_details.$": "$.query_details"
        }
        Next       = "EvaluateQueryStatus"
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
            Next = "QueryFinishedSuccessfully"
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

      # Step 4: Fetch Terraform files from GitHub
      QueryFinishedSuccessfully = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "fetch_terraform_files",
          "user_api_usage.$": "$.user_api_usage",
          "users.$": "$.users",
          "metadata.$": "$.metadata",
          "iam_data.$": "$.iam_data",
          "roles.$": "$.roles",
          "query_details.$": "$.query_details",
          "query_results_count.$": "$.query_results_count"
        }
        Next       = "ParseTerraformPolicies"
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

      # Step 5: Parse Terraform policies and generate recommendations
      ParseTerraformPolicies = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "parse_terraform_policies",
          "terraform_files.$": "$.terraform_files",
          "user_api_usage.$": "$.user_api_usage",
          "users.$": "$.users",
          "metadata.$": "$.metadata",
          "iam_data.$": "$.iam_data",
          "roles.$": "$.roles",
          "query_details.$": "$.query_details",
          "query_results_count.$": "$.query_results_count",
          "terraform_files_count.$": "$.terraform_files_count"
        }
        Next       = "CheckRecommendations"
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

      # Check if we have recommendations to create a PR for
      CheckRecommendations = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.recommendations_count"
            NumericGreaterThan = 0
            Next = "GenerateGitHubPR"
          }
        ]
        Default = "NoRecommendationsFound"
      }

      # Step 6: Generate GitHub PR with recommendations
      GenerateGitHubPR = {
        Type     = "Task"
        Resource = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
        Parameters = {
          "step": "generate_github_pr",
          "policy_recommendations.$": "$.policy_recommendations",
          "terraform_files.$": "$.terraform_files",
          "users.$": "$.users",
          "user_api_usage.$": "$.user_api_usage",
          "metadata.$": "$.metadata",
          "iam_data.$": "$.iam_data",
          "roles.$": "$.roles",
          "query_details.$": "$.query_details",
          "query_results_count.$": "$.query_results_count",
          "terraform_files_count.$": "$.terraform_files_count",
          "recommendations_count.$": "$.recommendations_count"
        }
        Next       = "AnalysisAndPRCompleted"
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

      # No recommendations found
      NoRecommendationsFound = {
        Type = "Pass"
        Result = {
          message = "IAM analysis completed - no optimization recommendations found"
          workflow_status = "complete_no_recommendations"
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