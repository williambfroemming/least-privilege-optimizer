resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "OverlyPermissiveReadAndWrite",
        Effect   = "Allow",
        Action   = [
          "s3:*",
          "athena:*",
          "glue:*",
          "cloudwatch:Get*",
          "cloudwatch:PutMetricData",
          "dynamodb:Scan",
          "kms:Decrypt",
          "iam:List*",
          "iam:Get*",
          "lambda:InvokeFunction",
          "sts:AssumeRole"
        ],
        Resource = "*"
      }
    ]
  })
}
