provider "aws" {
    region = "us-east-1"
}

# Import our module
# Update your module call in main.tf to include Step Function variables:

module "iam_analyzer" {
  source  = "../../terraform/modules/iam-parser"
  tf_path = "."
  
  # Required variables
  environment = "dev"
  github_repo = "williambfroemming/least-privilege-optimizer"
  
  # Step Function configuration - ADD THESE
  create_step_function = true
  enable_daily_schedule = false  # Weekly is better for testing
  
  # Testing settings
  enable_test_mode      = true
  force_lambda_rebuild  = true
  force_destroy_bucket  = true
  
  # CloudTrail configuration for testing
  enable_cloudtrail_data_lake   = true
  cloudtrail_retention_days     = 30
  
  # GitHub token configuration
  github_token_ssm_path = "/github-tokens/iam-analyzer"
  
  # Automation settings - Update this for weekly
  schedule_expression = "cron(0 6 ? * SUN *)"  # Weekly on Sundays
  
  # Lambda configuration
  lambda_timeout     = 300
  lambda_memory_size = 256
  
  # Storage configuration
  s3_prefix             = "iam-analysis"
  lambda_function_name  = "iam-analyzer"
  
  # Monitoring
  enable_monitoring  = true
  log_retention_days = 7
  
  # Tags
  tags = {
    Project     = "IAM-Analyzer"
    ManagedBy   = "Terraform"
    Environment = "dev"
    Owner       = "ScopeDown Team"
    Purpose     = "Automated IAM least privilege analysis"
    Testing     = "true"
  }
}

# S3 bucket to store the React web application
resource "aws_s3_bucket" "web_app" {
    bucket = "react-web-app-bucket-${random_id.suffix.hex}"
    
    tags = {
      Purpose = "Web application hosting"
    }
}

resource "random_id" "suffix" {
    byte_length = 4
}

# Bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "web_app" {
    bucket = aws_s3_bucket.web_app.id
    
    rule {
        object_ownership = "BucketOwnerPreferred"
    }
}

# Make the bucket publicly accessible
resource "aws_s3_bucket_public_access_block" "web_app" {
    bucket = aws_s3_bucket.web_app.id

    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
}

# Bucket ACL
resource "aws_s3_bucket_acl" "web_app" {
    depends_on = [
        aws_s3_bucket_ownership_controls.web_app,
        aws_s3_bucket_public_access_block.web_app,
    ]
    bucket = aws_s3_bucket.web_app.id
    acl    = "public-read"
}

# Bucket policy to allow public read access
resource "aws_s3_bucket_policy" "web_app" {
    bucket = aws_s3_bucket.web_app.id
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Sid       = "PublicReadGetObject"
                Effect    = "Allow"
                Principal = "*"
                Action    = "s3:GetObject"
                Resource  = "${aws_s3_bucket.web_app.arn}/*"
            }
        ]
    })
}

# S3 bucket website configuration
resource "aws_s3_bucket_website_configuration" "web_app" {
    bucket = aws_s3_bucket.web_app.id
    index_document {
        suffix = "index.html"
    }
    error_document {
        key = "index.html"
    }
}

# CloudFront Origin Access Identity
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
    comment = "access-identity-react-web-app"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "web_app" {
    origin {
        domain_name = aws_s3_bucket_website_configuration.web_app.website_endpoint
        origin_id   = "S3-${aws_s3_bucket.web_app.bucket}"

        custom_origin_config {
            http_port              = 80
            https_port             = 443
            origin_protocol_policy = "http-only"
            origin_ssl_protocols   = ["TLSv1.2"]
        }
    }

    enabled             = true
    is_ipv6_enabled     = true
    default_root_object = "index.html"

    default_cache_behavior {
        allowed_methods        = ["GET", "HEAD"]
        cached_methods         = ["GET", "HEAD"]
        target_origin_id       = "S3-${aws_s3_bucket.web_app.bucket}"
        viewer_protocol_policy = "redirect-to-https"
        min_ttl                = 0
        default_ttl            = 3600
        max_ttl                = 86400

        forwarded_values {
            query_string = false
            cookies {
                forward = "none"
            }
        }
    }

    # Cache behavior with precedence 0
    ordered_cache_behavior {
        path_pattern     = "/*"
        allowed_methods  = ["GET", "HEAD"]
        cached_methods   = ["GET", "HEAD"]
        target_origin_id = "S3-${aws_s3_bucket.web_app.bucket}"

        forwarded_values {
            query_string = false
            cookies {
                forward = "none"
            }
        }

        min_ttl                = 0
        default_ttl            = 3600
        max_ttl                = 86400
        compress               = true
        viewer_protocol_policy = "redirect-to-https"
    }

    price_class = "PriceClass_100"

    restrictions {
        geo_restriction {
            restriction_type = "none"
        }
    }

    viewer_certificate {
        cloudfront_default_certificate = true
    }

    # Handle SPA routing
    custom_error_response {
        error_code         = 403
        response_code      = 200
        response_page_path = "/index.html"
    }

    custom_error_response {
        error_code         = 404
        response_code      = 200
        response_page_path = "/index.html"
    }
    
    tags = {
      Purpose = "Web application CDN"
    }
}

# Outputs
output "s3_bucket_name" {
    value = aws_s3_bucket.web_app.bucket
}

output "cloudfront_domain_name" {
    value = aws_cloudfront_distribution.web_app.domain_name
}

# IAM Analyzer outputs
output "iam_analyzer_bucket" {
    description = "S3 bucket where IAM analysis results are stored"
    value = module.iam_analyzer.s3_bucket_name
}

output "lambda_function_name" {
    description = "Name of the IAM analyzer Lambda function"
    value = module.iam_analyzer.lambda_function_name
}

output "cloudtrail_info" {
    description = "CloudTrail Lake information for API usage analysis"
    value = {
        event_data_store_arn = module.iam_analyzer.cloudtrail_event_data_store_arn
        event_data_store_name = module.iam_analyzer.cloudtrail_event_data_store_name
        sample_queries = module.iam_analyzer.sample_queries
    }
}

output "setup_instructions" {
  description = "Setup instructions for IAM Analyzer"
  value = {
    github_token_command = "aws ssm put-parameter --name '${module.iam_analyzer.github_token_ssm_path}' --value 'your_github_token_here' --type SecureString"
    test_lambda_command  = "aws lambda invoke --function-name '${module.iam_analyzer.lambda_function_name}' response.json"
    s3_bucket           = module.iam_analyzer.s3_bucket_name
    schedule            = "Runs automatically every day"
    test_mode           = "Currently in test mode - uses mock data (no AWS API costs)"
    cloudtrail_lake     = module.iam_analyzer.cloudtrail_event_data_store_name
  }
}

output "next_steps" {
  description = "What to do after deployment"
  value = [
    "1. Store your GitHub token: aws ssm put-parameter --name '/github-tokens/iam-analyzer' --value 'ghp_your_token' --type SecureString",
    "2. Test the Lambda: aws lambda invoke --function-name '${module.iam_analyzer.lambda_function_name}' response.json",
    "3. Check CloudWatch logs: aws logs describe-log-groups --log-group-name-prefix '/aws/lambda/${module.iam_analyzer.lambda_function_name}'",
    "4. Query CloudTrail Lake directly: Use the CloudTrail console Lake section or AWS CLI",
    "5. Check the created PR in your repository",
    "6. When ready for production, set enable_test_mode = false and redeploy"
  ]
}

# Add these outputs to your main.tf after the existing outputs:

output "step_function_info" {
  description = "Step Function workflow information"
  value = {
    arn         = module.iam_analyzer.step_function_arn
    name        = module.iam_analyzer.step_function_name
    console_url = module.iam_analyzer.step_function_console_url
  }
}

output "workflow_test_command" {
  description = "Command to test the Step Function workflow"
  value = module.iam_analyzer.step_function_arn != null ? "aws stepfunctions start-execution --state-machine-arn '${module.iam_analyzer.step_function_arn}' --name 'test-$(date +%s)' --input '{}'" : "Step Function not created"
}