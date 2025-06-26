# Build Lambda function and layer (only if Lambda is enabled)
resource "null_resource" "lambda_build" {
  count = var.create_lambda ? 1 : 0
  
  provisioner "local-exec" {
    command     = "cd lambda && chmod +x build_lambda.sh && ./build_lambda.sh"
    working_dir = path.module
  }
  
  triggers = {
    # More specific triggers
    build_script     = fileexists("${path.module}/lambda/build_lambda.sh") ? filebase64sha256("${path.module}/lambda/build_lambda.sh") : ""
    lambda_source    = fileexists("${path.module}/lambda/index.py") ? filebase64sha256("${path.module}/lambda/index.py") : ""
    requirements     = fileexists("${path.module}/lambda/requirements.txt") ? filebase64sha256("${path.module}/lambda/requirements.txt") : ""
    force_rebuild    = var.force_lambda_rebuild ? timestamp() : "stable"
  }
}

# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "dependencies" {
  count = var.create_lambda ? 1 : 0
  
  filename                 = "${path.module}/lambda/layer.zip"
  layer_name              = "${local.name_prefix}-dependencies"
  description             = "Dependencies for IAM Analyzer Lambda"
  compatible_runtimes     = [var.python_runtime]
  compatible_architectures = ["x86_64"]
  source_code_hash        = null_resource.lambda_build[0].id
  
  depends_on = [null_resource.lambda_build]
  
  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Log Group - Created before Lambda to control retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  count = var.create_lambda ? 1 : 0
  
  name              = "/aws/lambda/${local.name_prefix}-${var.lambda_function_name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Component = "lambda-logs"
  })
}

# Lambda function with lifecycle management
resource "aws_lambda_function" "iam_analyzer_engine_tf_deployed" {
  count = var.create_lambda ? 1 : 0
  
  function_name = "${local.name_prefix}-${var.lambda_function_name}"
  role         = aws_iam_role.iam_analyzer_lambda_role[0].arn
  handler      = "index.lambda_handler"
  runtime      = var.python_runtime
  timeout      = var.lambda_timeout
  memory_size  = var.lambda_memory_size

  filename         = "${path.module}/lambda/iam_analyzer_engine.zip"
  source_code_hash = null_resource.lambda_build[0].id
  
  # Use the layer for dependencies
  layers = var.create_lambda && length(aws_lambda_layer_version.dependencies) > 0 ? [aws_lambda_layer_version.dependencies[0].arn] : []

 environment {
  variables = {
    S3_BUCKET                  = aws_s3_bucket.iam_parser_output.bucket
    S3_PREFIX                  = var.s3_prefix
    LOG_LEVEL                  = var.environment == "prod" ? "WARNING" : "DEBUG"
    ENVIRONMENT                = var.environment
    ANALYZER_ARN               = var.analyzer_arn
    GITHUB_REPO                = var.github_repo
    IAM_ANALYZER_TEST_MODE     = var.enable_test_mode ? "true" : "false"
    GITHUB_TOKEN_SSM_PATH      = var.github_token_ssm_path  # Add this line
  }
}

  tags = local.common_tags

  depends_on = [
    null_resource.lambda_build,
    aws_lambda_layer_version.dependencies,
    aws_cloudwatch_log_group.lambda_logs
  ]
  
  lifecycle {
    ignore_changes = [
      source_code_hash
    ]
    replace_triggered_by = [
      null_resource.lambda_build[0]
    ]
  }
}

# Simple error monitoring (only if monitoring is enabled)
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = var.create_lambda && var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${local.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Lambda error monitoring"

  dimensions = {
    FunctionName = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].function_name
  }

  tags = local.common_tags
}