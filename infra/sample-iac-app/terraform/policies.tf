
# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-22 21:12:35
# Finding ID: ff720836-1d0c-4551-86a6-88d758993273
# Resource: dave_observer_test
# Removed unused services: cloudwatch, glue, logs, s3
# This modification removes 4 unused service permissions
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
          "athena:*",                     # All Athena actions
          "*",                       # All Glue actions (overkill for most analysts)
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
          "lambda:*"                          # Too much
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
          "iam:GetRole",
          "iam:ListRoles"
        ],
        Resource: "*"
      },
      {
        Sid: "CloudWatchLogsAccess",
        Effect: "Allow",
        Action: [
          "DescribeLogGroups",
          "GetLogEvents",
          "FilterLogEvents",
          "PutLogEvents"                # Not always needed
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
          "GetLogEvents",
          "DescribeLogStreams",
          "DescribeLogGroups",
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