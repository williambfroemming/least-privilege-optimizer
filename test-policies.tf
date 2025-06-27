# Test Policy File
# Created by IAM Optimizer Test at 2025-06-26T18:44:13.606240

resource "aws_iam_user" "test_user" {
  name = "test-user-20250626184413"
}

resource "aws_iam_user_policy" "test_policy" {
  name = "test-policy"
  user = aws_iam_user.test_user.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
      }
    ]
  })
}
