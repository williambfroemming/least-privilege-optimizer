provider "aws" {
    region = "us-east-1"
}

# Import our module
# module "iam_parser" {
#   source  = "../../terraform/modules/iam-parser"
#   tf_path = "../../sample-iac-app/terraform"
  
#   # Required variable
#   environment = "dev"
  
#   # Optional: customize naming
#   s3_prefix             = "iam-analysis"
#   lambda_function_name  = "iam-analyzer"
  
#   # Optional: add additional tags
#   tags = {
#     Project     = "IAM-Analyzer"
#     ManagedBy   = "Terraform"
#     Environment = "dev"
#     Owner       = "ScopeDown Team"
#   }
# }

# Test IAM Resource
resource "aws_iam_user" "test_user" {
  name = "static-parser-test-user"
}

resource "aws_iam_role" "test_role" {
  name = "static-parser-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# S3 bucket to store the React web application
resource "aws_s3_bucket" "web_app" {
    bucket = "react-web-app-bucket-${random_id.suffix.hex}"
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
}

output "s3_bucket_name" {
    value = aws_s3_bucket.web_app.bucket
}

output "cloudfront_domain_name" {
    value = aws_cloudfront_distribution.web_app.domain_name
}

# output "iam_scan_output" {
#   description = "IAM analysis results and metadata"
#   value = {
#     bucket            = module.iam_parser.s3_bucket_name     # CHANGED FROM iam_s3_bucket
#     bucket_arn        = module.iam_parser.s3_bucket_arn
#     latest_output_key = module.iam_parser.latest_output_key
#     s3_prefix         = module.iam_parser.s3_prefix
#     aws_region        = module.iam_parser.aws_region
#   }
# }