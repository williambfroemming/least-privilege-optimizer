# IAM Users and Policies
# This file contains IAM resources for our application

resource "aws_iam_user" "alice_analyst" {
  name = "alice-analyst-test"
  path = "/analysts/"
  
  tags = {
    Department = "Analytics"
    Purpose    = "DataAnalysis"
  }
}

resource "aws_iam_user" "bob_developer" {
  name = "bob-dev-test"
  path = "/developers/"
  
  tags = {
    Department = "Engineering"
    Purpose    = "Development"
  }
}

resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-policy"
  user = aws_iam_user.alice_analyst.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AnalyticsAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "athena:StartQueryExecution",
          "athena:GetQueryResults",
          "athena:CreateDataCatalog",
          "athena:DeleteWorkGroup",
          "glue:*",
          "dynamodb:Scan",
          "iam:List*",
          "iam:Get*",
          "lambda:InvokeFunction",
          "sts:AssumeRole",
          "cloudwatch:PutMetricData",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy" "bob_developer_policy" {
  name = "bob-developer-policy"
  user = aws_iam_user.bob_developer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DeveloperAccess"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:DeleteFunction",
          "lambda:UpdateFunctionCode",
          "lambda:InvokeFunction",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketPolicy",
          "iam:GetRole",
          "iam:ListRoles",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# Additional resources...
resource "aws_s3_bucket" "app_data" {
  bucket = "my-app-data-bucket"
}
