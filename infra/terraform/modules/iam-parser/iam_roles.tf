resource "aws_iam_role" "iam_analyzer_lambda_role" {
  name = "iam-analyzer-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement: [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_logging_policy" {
  name        = "LambdaBasicExecutionLogs"
  description = "Allows Lambda to write to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement: [
      {
        Effect = "Allow",
        Action = "logs:CreateLogGroup",
        Resource = "arn:aws:logs:us-east-1:904610147891:*"
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:us-east-1:904610147891:log-group:/aws/lambda/iam-analyzer-engine:*"
      }
    ]
  })
}

resource "aws_iam_policy" "access_analyzer_permissions" {
  name        = "AccessAnalyzerPermissions"
  description = "Permissions for Access Analyzer integration"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement: [
      {
        Sid: "VisualEditor0",
        Effect: "Allow",
        Action: [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:CheckAccessNotGranted",
          "access-analyzer:StartPolicyGeneration",
          "access-analyzer:GetGeneratedPolicy",
          "access-analyzer:ValidatePolicy",
          "access-analyzer:CheckNoPublicAccess",
          "access-analyzer:CancelPolicyGeneration",
          "access-analyzer:ListPolicyGenerations",
          "access-analyzer:CheckNoNewAccess"
        ],
        Resource: "*"
      },
      {
        Sid: "VisualEditor1",
        Effect: "Allow",
        Action: "access-analyzer:*",
        Resource: "arn:aws:access-analyzer:*:904610147891:analyzer/*"
      },
      {
        Sid: "VisualEditor2",
        Effect: "Allow",
        Action: "access-analyzer:*",
        Resource: "arn:aws:access-analyzer:*:904610147891:analyzer/*/archive-rule/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs_attach" {
  role       = aws_iam_role.iam_analyzer_lambda_role.name
  policy_arn = aws_iam_policy.lambda_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "access_analyzer_attach" {
  role       = aws_iam_role.iam_analyzer_lambda_role.name
  policy_arn = aws_iam_policy.access_analyzer_permissions.arn
}

resource "aws_iam_policy" "lambda_s3_access" {
  name        = "lambda-s3-access"
  description = "Allow Lambda to read/write objects in the parser output bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement: [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.iam_parser_output.arn,
          "${aws_s3_bucket.iam_parser_output.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_access_attach" {
  role       = aws_iam_role.iam_analyzer_lambda_role.name
  policy_arn = aws_iam_policy.lambda_s3_access.arn
}