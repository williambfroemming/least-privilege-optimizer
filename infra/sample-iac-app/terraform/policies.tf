resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice_analyst_policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LeastPrivilegeAccess"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "iam:ListRoles",
          "s3:PutObject"
        ]
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_user_policy" "bob_dev_policy" {
  name = "bob_dev_policy"
  user = aws_iam_user.bob_dev_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LeastPrivilegeAccess"
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "lambda:ListFunctions20150331"
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