# SNS topic for security notifications
resource "aws_sns_topic" "security_notifications" {
  name = "${local.name_prefix}-security-notifications"

  tags = merge(var.tags, {
    Purpose     = "Security notifications for IAM analyzer"
    Environment = var.environment
  })
}

resource "aws_sns_topic_policy" "security_notifications_policy" {
  arn = aws_sns_topic.security_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "s3.amazonaws.com"
        },
        Action = "SNS:Publish",
        Resource = aws_sns_topic.security_notifications.arn,
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}
