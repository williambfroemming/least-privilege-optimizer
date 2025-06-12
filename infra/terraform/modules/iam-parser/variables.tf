# Core functionality variables
variable "tf_path" {
  description = "Path to the Terraform project to be analyzed"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._/-]+$", var.tf_path))
    error_message = "tf_path must be a valid file path."
  }
}

# S3 Configuration
variable "s3_bucket_name" {
  description = "S3 bucket name for output (will be created if not exists)"
  type        = string
  default     = null
  
  validation {
    condition = var.s3_bucket_name == null || (
      length(var.s3_bucket_name) >= 3 && 
      length(var.s3_bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.s3_bucket_name))
    )
    error_message = "S3 bucket name must be between 3-63 characters, lowercase, and follow AWS naming rules."
  }
}

variable "s3_prefix" {
  description = "Prefix inside the S3 bucket where files will be stored"
  type        = string
  default     = "iam-parsed"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-_/]+$", var.s3_prefix)) && !startswith(var.s3_prefix, "/") && !endswith(var.s3_prefix, "/")
    error_message = "S3 prefix must contain only alphanumeric characters, hyphens, underscores, and forward slashes, and cannot start or end with a forward slash."
  }
}

# Lambda Configuration
variable "lambda_function_name" {
  description = "Name for the Lambda function (will be prefixed automatically)"
  type        = string
  default     = "iam-analyzer-engine"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-_]+$", var.lambda_function_name)) && length(var.lambda_function_name) <= 64
    error_message = "Lambda function name must contain only alphanumeric characters, hyphens, and underscores, and be no more than 64 characters."
  }
}

variable "lambda_timeout" {
  description = "Timeout for the IAM analyzer Lambda function (seconds)"
  type        = number
  default     = 10
  
  validation {
    condition     = var.lambda_timeout >= 1 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds (15 minutes)."
  }
}

variable "lambda_memory_size" {
  description = "Memory allocation for Lambda function (MB)"
  type        = number
  default     = 128
  
  validation {
    condition = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

# CloudWatch Logs Configuration
variable "log_retention_days" {
  description = "CloudWatch log retention period (days)"
  type        = number
  default     = 7
  
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention value: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, or 3653 days."
  }
}

# Naming and Organization
variable "name_prefix" {
  description = "Prefix for resource names to avoid conflicts (leave empty for auto-generation)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.name_prefix == "" || can(regex("^[a-zA-Z0-9-]+$", var.name_prefix))
    error_message = "Name prefix must contain only alphanumeric characters and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# Resource Tagging
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project   = "IAM-Analyzer"
    ManagedBy = "Terraform"
  }
  
  validation {
    condition = alltrue([
      for k, v in var.tags : can(regex("^[a-zA-Z0-9+\\-=._:/@\\s]+$", k)) && can(regex("^[a-zA-Z0-9+\\-=._:/@\\s]+$", v))
    ])
    error_message = "Tag keys and values must contain only valid AWS tag characters."
  }
}

# Testing and development variables
variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alarms"
  type        = bool
  default     = true
}

variable "force_destroy_bucket" {
  description = "Allow bucket to be destroyed even with objects (useful for testing)"
  type        = bool
  default     = false
}

variable "python_runtime" {
  description = "Python runtime version for Lambda"
  type        = string
  default     = "python3.9"
  
  validation {
    condition     = contains(["python3.8", "python3.9", "python3.10", "python3.11"], var.python_runtime)
    error_message = "Python runtime must be a supported Lambda version."
  }
}

variable "create_lambda" {
  description = "Whether to create the Lambda function (useful for testing S3 only)"
  type        = bool
  default     = true
}