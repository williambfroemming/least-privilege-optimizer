variable "tf_path" {
  description = "Path to the Terraform project to be analyzed"
  type        = string
}

variable "s3_bucket_name" {
  description = "Optional S3 bucket name for output (will be created if not exists)"
  type        = string
  default     = "iam-parser-shared-bucket"
}

variable "s3_prefix" {
  description = "Prefix inside the S3 bucket where files will be stored"
  type        = string
  default     = "iam-parsed"
}

variable "lambda_function_name" {
  description = "iam-analyzer-engine-test-deployment"
  type        = string
  default     = "iam-analyzer-engine-tf-deployed"
}

variable "lambda_timeout" {
  description = "Timeout for the IAM analyzer Lambda function"
  type        = number
  default     = 10
}