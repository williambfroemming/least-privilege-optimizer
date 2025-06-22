
# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-22 21:12:30
# Finding ID: 88169d3f-40b1-4148-92c3-dd74d76f78c9
# Resource: alice_analyst_test
# Removed unused services: athena, cloudwatch, dynamodb, glue, iam, kms, lambda, s3, sts
# This modification removes 9 unused service permissions
# Based on AWS Access Analyzer findings for least privilege access
#
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
          "*",                         # Full S3 access
          "*",                     # All Athena actions
          "*",                       # All Glue actions (overkill for most analy)
          "cloudwatch:Get*",              # OK
          "cloudwatch:PutMetricData",     # Write perms analysts shouldn't need
          "dynamodb:Scan",                # Too broad for sensitive data
          "kms:Decrypt",                  # Dangerous without restrictions
          "iam:List*",                    # Allows recon
          "iam:Get*",                     # More recon
          "lambda:InvokeFunction",        # Could be misused
          "sts:AssumeRole"                # Very risky unless scoped tightly
        ],
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy" "bob_dev_policy" {
  name = "bob-dev-test-policy"
  user = aws_iam_user.bob_dev_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "LambdaOverreach",
        Effect: "Allow",
        Action: [
          "*"                          # Too much
        ],
        Resource: "*"
      },
      {
        Sid: "S3FullBucketAccess",
        Effect: "Allow",
        Action: [
          "PutObject",
          "GetObject",
          "ListBucket",
          "DeleteObject",                  # Excessive
          "PutBucketPolicy",               # Definitely too much
          "GetBucketAcl"
        ],
        Resource: [
          "arn:aws:ucb-capstone-bucket",
          "arn:aws:ucb-capstone-bucket/*"
        ]
      },
      {
        Sid: "IAMReconAccess",
        Effect: "Allow",
        Action: [
          "GetRole",
          "ListRoles"
        ],
        Resource: "*"
      },
      {
        Sid: "CloudWatchLogsAccess",
        Effect: "Allow",
        Action: [
          "logs:DescribeLogGroups",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:PutLogEvents"                # Not always needed
        ],
        Resource: "*"
      },
      {
        Sid: "ECSAndECRAccess",
        Effect: "Allow",
        Action: [
          "ecs:ListClusters",
          "ecs:DescribeTasks",
          "ecr:GetAuthorizationToken",
          "ecr:DescribeRepositories"
        ],
        Resource: "*"
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
          "GetObject",
          "ListBucket",
          "GetMetricData",
          "GetTables"
        ],
        Resource = "*"
      }
    ]
  })
}