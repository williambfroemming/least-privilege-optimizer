resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LeastPrivilegeAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "iam:ListRoles",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_user_policy" "bob_dev_policy" {
  name = "bob-dev-test-policy"
  user = aws_iam_user.bob_dev_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LeastPrivilegeAccess"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions20150331",
          "iam:ListRoles"
        ]
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_user_policy_attachment" "charlie_admin_access" {
  user       = aws_iam_user.charlie_admin_test.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_user_policy" "dave_observer_policy" {
  name = "dave-observer-test-policy"
  user = aws_iam_user.dave_observer_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:GetLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups",
          "s3:GetObject",
          "s3:ListBucket",
          "cloudwatch:GetMetricData",
          "glue:GetTables"
        ],
        Resource = "*"
      }
    ]
  })
}