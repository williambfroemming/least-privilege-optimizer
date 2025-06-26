# eventbridge.tf
resource "aws_cloudwatch_event_rule" "lambda_schedule" {
  count = var.create_lambda ? 1 : 0
  
  name                = "${local.name_prefix}-schedule"
  description         = "Trigger IAM analyzer Lambda on schedule"
  schedule_expression = var.schedule_expression
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  count = var.create_lambda ? 1 : 0
  
  rule      = aws_cloudwatch_event_rule.lambda_schedule[0].name
  target_id = "IAMAnalyzerLambdaTarget"
  arn       = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.create_lambda ? 1 : 0
  
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_analyzer_engine_tf_deployed[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_schedule[0].arn
}