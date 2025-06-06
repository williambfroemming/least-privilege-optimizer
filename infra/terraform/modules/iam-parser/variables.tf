variable "tf_path" {
  description = "Path to folder containing Terraform files to scan"
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

variable "lambda_zip_path" {
  description = "../../../lambdas/test/test_lambda_deployment.py"
  type        = string
}

variable "lambda_function_name" {
  description = "iam-analyzer-engine-test-deployment"
  type        = string
  default     = "iam-analyzer-engine-test"
}
