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
          "s3:GetBucketLocation",
          "s3:PutObject",
          "iam:ListRoles"
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