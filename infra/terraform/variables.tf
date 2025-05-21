variable "account_id" {
  description = "AWS account ID"
  type        = string
  default     = "904610147891"
}


variable "aws_region" {
  description = "AWS region to deploy resources in"
  type        = string
  default     = "us-east-1" # or leave out default and require it in tfvars
}

