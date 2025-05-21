# Admin: Full access
resource "aws_iam_role_policy_attachment" "test_admin_admin_access" {
  role       = aws_iam_role.test_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "test_data_engineer_policy" {
  name = "test-data-engineer-policy"
  role = aws_iam_role.test_data_engineer.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid = "DataLakeAccess"
        Effect = "Allow"
        Action = [
          "s3:*",
          "athena:*",
          "glue:*",
          "logs:*"
        ]
        Resource = "*"
      },
      {
        Sid = "EC2AdminForTesting"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:RunInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ]
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_role_policy" "test_support_analyst_policy" {
  name = "test-support-analyst-policy"
  role = aws_iam_role.test_support_analyst.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid = "ReadOnlySupport"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "support:*",
          "ce:GetCostAndUsage",
          "cloudwatch:GetMetricData",
          "logs:GetLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid = "LightEC2Diagnostic"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:GetConsoleOutput"
        ]
        Resource = "*"
      }
    ]
  })
}
