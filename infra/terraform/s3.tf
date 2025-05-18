resource "aws_s3_bucket" "capstone_main" {
  bucket = "ucb-capstone-bucket"

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket" "capstone_athena" {
  bucket = "ucb-capstone-athena-results"

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket" "capstone_cloudtrail" {
  bucket = "ucb-capstone-aws-cloudtrail-logs"

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket" "global_cloudtrail" {
  bucket = "aws-cloudtrail-logs-904610147891-d46a1694"

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
