# Data sources to get current AWS account ID and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "iam_analyzer_lambda_role" {
  count = var.create_lambda ? 1 : 0
  name  = "${local.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_policy" "lambda_logging_policy" {
  count       = var.create_lambda ? 1 : 0
  name        = "${local.name_prefix}-logging-policy"
  description = "Allows Lambda to write to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "logs:CreateLogGroup",
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-${var.lambda_function_name}:*"
      }
    ]
  })

  tags = local.common_tags
}

# IMPROVED: More restrictive S3 policy with least privilege
resource "aws_iam_policy" "lambda_s3_access" {
  count       = var.create_lambda ? 1 : 0
  name        = "${local.name_prefix}-s3-access-policy"
  description = "Allow Lambda to read/write objects in specific S3 prefix only"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "${aws_s3_bucket.iam_parser_output.arn}/${var.s3_prefix}/*"
      },
      {
        Effect = "Allow",
        Action = "s3:ListBucket",
        Resource = aws_s3_bucket.iam_parser_output.arn,
        Condition = {
          StringLike = {
            "s3:prefix" = "${var.s3_prefix}/*"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# IMPROVED: More restrictive Access Analyzer permissions - ADD COUNT HERE
resource "aws_iam_policy" "access_analyzer_permissions" {
  count       = var.create_lambda ? 1 : 0
  name        = "${local.name_prefix}-access-analyzer-policy"
  description = "Permissions for Access Analyzer integration with least privilege"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ValidatePolicy",
          "access-analyzer:CheckAccessNotGranted",
          "access-analyzer:CheckNoNewAccess"
        ],
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

# Policy attachments with correct resource references
resource "aws_iam_role_policy_attachment" "lambda_logs_attach" {
  count      = var.create_lambda ? 1 : 0
  role       = aws_iam_role.iam_analyzer_lambda_role[0].name
  policy_arn = aws_iam_policy.lambda_logging_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "access_analyzer_attach" {
  count      = var.create_lambda ? 1 : 0
  role       = aws_iam_role.iam_analyzer_lambda_role[0].name
  policy_arn = aws_iam_policy.access_analyzer_permissions[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_s3_access_attach" {
  count      = var.create_lambda ? 1 : 0
  role       = aws_iam_role.iam_analyzer_lambda_role[0].name
  policy_arn = aws_iam_policy.lambda_s3_access[0].arn
}