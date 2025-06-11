# Build Lambda function and layer
resource "null_resource" "lambda_build" {
  provisioner "local-exec" {
    command     = "cd lambda && chmod +x build_lambda.sh && ./build_lambda.sh"
    working_dir = path.module
  }
  
  triggers = {
    code_hash         = filebase64sha256("${path.module}/lambda/index.py")
    upload_hash       = fileexists("${path.module}/lambda/upload.py") ? filebase64sha256("${path.module}/lambda/upload.py") : ""
    requirements_hash = filebase64sha256("${path.module}/lambda/requirements.txt")
    build_script_hash = filebase64sha256("${path.module}/lambda/build_lambda.sh")
  }
}

# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "dependencies" {
  filename            = "${path.module}/lambda/layer.zip"
  layer_name          = "${local.name_prefix}-dependencies"
  description         = "Dependencies for IAM Analyzer Lambda"
  compatible_runtimes = ["python3.9", "python3.11"]
  compatible_architectures = ["x86_64"]
  
  depends_on = [null_resource.lambda_build]
  
  # Use conditional hash to avoid file not found error
  source_code_hash = fileexists("${path.module}/lambda/layer.zip") ? filebase64sha256("${path.module}/lambda/layer.zip") : null
}

# CloudWatch Log Group - Created before Lambda to control retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.name_prefix}-${var.lambda_function_name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(var.tags, {
    Environment = var.environment
  })
}

# Lambda function with enhanced configuration
resource "aws_lambda_function" "iam_analyzer_engine_tf_deployed" {
  function_name = "${local.name_prefix}-${var.lambda_function_name}"
  role          = aws_iam_role.iam_analyzer_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"  # Match your upload.py
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = "${path.module}/lambda/iam_analyzer_engine.zip"
  source_code_hash = fileexists("${path.module}/lambda/iam_analyzer_engine.zip") ? filebase64sha256("${path.module}/lambda/iam_analyzer_engine.zip") : null
  
  # Use the layer for dependencies
  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      S3_BUCKET   = aws_s3_bucket.iam_parser_output.bucket
      S3_PREFIX   = var.s3_prefix
      LOG_LEVEL   = "INFO"
      ENVIRONMENT = var.environment
    }
  }

  tags = merge(var.tags, {
    Environment = var.environment
  })

  depends_on = [
    null_resource.lambda_build,
    aws_lambda_layer_version.dependencies,
    aws_iam_role_policy_attachment.lambda_logs_attach,
    aws_iam_role_policy_attachment.access_analyzer_attach,
    aws_iam_role_policy_attachment.lambda_s3_access_attach,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# Optional: CloudWatch alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda errors"
  alarm_actions       = [] # Add SNS topic ARN here if you want notifications

  dimensions = {
    FunctionName = aws_lambda_function.iam_analyzer_engine_tf_deployed.function_name
  }

  tags = merge(var.tags, {
    Environment = var.environment
  })
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "${local.name_prefix}-lambda-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "${var.lambda_timeout * 1000 * 0.8}" # 80% of timeout in milliseconds
  alarm_description   = "This metric monitors lambda duration"

  dimensions = {
    FunctionName = aws_lambda_function.iam_analyzer_engine_tf_deployed.function_name
  }

  tags = merge(var.tags, {
    Environment = var.environment
  })
}