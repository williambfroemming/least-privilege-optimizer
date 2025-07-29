locals {
  lambda_functions = {
    "read-s3" = {
      handler      = "index.lambda_handler"
      timeout      = 30
      memory_size  = 128
      directory    = "step1_read_s3"
      description  = "Read IAM data from S3"
    }
    "start-cloudtrail" = {
      handler      = "index.lambda_handler"
      timeout      = 60
      memory_size  = 256
      directory    = "step2_cloudtrail"
      description  = "Start CloudTrail Lake query"
    }
    "check-cloudtrail" = {
      handler      = "index.lambda_handler"
      timeout      = 60
      memory_size  = 256
      directory    = "step3_query_status"
      description  = "Check CloudTrail query status"
    }
    "fetch-terraform" = {
      handler      = "index.lambda_handler"
      timeout      = 300
      memory_size  = 512
      directory    = "step4_github_fetch"
      description  = "Fetch Terraform files from GitHub"
    }
    "parse-policies" = {
      handler      = "index.lambda_handler"
      timeout      = 180
      memory_size  = 1024
      directory    = "step5_parse_policies"
      description  = "Parse Terraform policies"
    }
    "apply-modifications" = {
      handler      = "index.lambda_handler"
      timeout      = 180
      memory_size  = 512
      directory    = "step6_apply_modifications"
      description  = "Apply safe modifications to Terraform files"
    }
    "github-pr" = {
      handler      = "index.lambda_handler"
      timeout      = 300
      memory_size  = 512
      directory    = "step7_github_pr"
      description  = "Create GitHub PR with modifications"
    }
  }
}

# Build all Lambda functions
resource "null_resource" "lambda_build_all" {
  count = var.create_lambda ? 1 : 0
  
  provisioner "local-exec" {
    command     = "chmod +x build_all_lambdas.sh && ./build_all_lambdas.sh"
    working_dir = "${path.module}/lambda"
  }
  
  triggers = {
    # Trigger rebuild when any source files change
    build_script = fileexists("${path.module}/lambda/build_all_lambdas.sh") ? filebase64sha256("${path.module}/lambda/build_all_lambdas.sh") : ""
    force_rebuild = var.force_lambda_rebuild ? timestamp() : "stable"
    
    # Individual function triggers
    step1_source = fileexists("${path.module}/lambda/step1_read_s3/index.py") ? filebase64sha256("${path.module}/lambda/step1_read_s3/index.py") : ""
    step2_source = fileexists("${path.module}/lambda/step2_cloudtrail/index.py") ? filebase64sha256("${path.module}/lambda/step2_cloudtrail/index.py") : ""
    step3_source = fileexists("${path.module}/lambda/step3_query_status/index.py") ? filebase64sha256("${path.module}/lambda/step3_query_status/index.py") : ""
    step4_source = fileexists("${path.module}/lambda/step4_github_fetch/index.py") ? filebase64sha256("${path.module}/lambda/step4_github_fetch/index.py") : ""
    step5_source = fileexists("${path.module}/lambda/step5_parse_policies/index.py") ? filebase64sha256("${path.module}/lambda/step5_parse_policies/index.py") : ""
    step6_source = fileexists("${path.module}/lambda/step6_apply_modifications/index.py") ? filebase64sha256("${path.module}/lambda/step6_apply_modifications/index.py") : ""
    step7_source = fileexists("${path.module}/lambda/step7_github_pr/index.py") ? filebase64sha256("${path.module}/lambda/step7_github_pr/index.py") : ""
  }
}

# CloudWatch Log Groups for each function
resource "aws_cloudwatch_log_group" "lambda_logs" {
  for_each = var.create_lambda ? local.lambda_functions : {}
  
  name              = "/aws/lambda/${local.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Component = "lambda-logs"
    Function  = each.key
  })
}

# Lambda functions - FIXED to avoid source_code_hash inconsistency
resource "aws_lambda_function" "iam_analyzer_functions" {
  for_each = var.create_lambda ? local.lambda_functions : {}
  
  function_name = "${local.name_prefix}-${each.key}"
  role         = aws_iam_role.iam_analyzer_lambda_role[0].arn
  handler      = each.value.handler
  runtime      = var.python_runtime
  timeout      = each.value.timeout
  memory_size  = each.value.memory_size
  description  = each.value.description

  filename = "${path.module}/lambda/${each.value.directory}/function.zip"
  
  # Use null_resource ID as source_code_hash to avoid inconsistency
  source_code_hash = null_resource.lambda_build_all[0].id

  environment {
    variables = {
      S3_BUCKET                       = aws_s3_bucket.iam_parser_output.bucket
      S3_PREFIX                       = var.s3_prefix
      LOG_LEVEL                       = var.environment == "prod" ? "WARNING" : "DEBUG"
      ENVIRONMENT                     = var.environment
      GITHUB_REPO                     = var.github_repo
      GITHUB_TOKEN_SSM_PATH           = var.github_token_ssm_path
      CLOUDTRAIL_EVENT_DATA_STORE_ARN = aws_cloudtrail_event_data_store.iam_analyzer_store.arn
      CLOUDTRAIL_RETENTION_DAYS       = var.cloudtrail_retention_days
    }
  }

  tags = merge(local.common_tags, {
    Function = each.key
  })

  depends_on = [
    null_resource.lambda_build_all,
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role.iam_analyzer_lambda_role
  ]
  
  # Lifecycle to handle source code changes properly
  lifecycle {
    replace_triggered_by = [
      null_resource.lambda_build_all[0]
    ]
  }
}

# Error monitoring for each function
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = var.create_lambda && var.enable_monitoring ? local.lambda_functions : {}
  
  alarm_name          = "${local.name_prefix}-${each.key}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Lambda error monitoring for ${each.key}"

  dimensions = {
    FunctionName = aws_lambda_function.iam_analyzer_functions[each.key].function_name
  }

  tags = merge(local.common_tags, {
    Function = each.key
  })
}