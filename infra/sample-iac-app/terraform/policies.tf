# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-26 01:13:47 UTC
# Based on AWS IAM Access Analyzer findings
# All permissions were found to be unused and have been removed for least privilege


# RECOMMENDATION SUMMARY for aws_iam_user.alice_analyst_test:
# - Finding ID: 65fffdff-cf21-44c0-b6a9-8b6692f0a913
# - Unused actions: 21
# - All permissions removed as they were unused
# - Policy now has empty statements array (grants no permissions)

resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  # LEAST PRIVILEGE POLICY: All previous permissions were unused according to Access Analyzer
  # This policy grants no permissions - only add what is actually needed based on real usage
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
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
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject",                  # Excessive
          "s3:PutBucketPolicy",               # Definitely too much
          "s3:GetBucketAcl"
        ],
        Resource: [
          "arn:aws:s3:::ucb-capstone-bucket",
          "arn:aws:s3:::ucb-capstone-bucket/*"
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