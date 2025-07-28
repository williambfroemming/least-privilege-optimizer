# cloudtrail-lake.tf - NEW FILE
# CloudTrail Lake Event Data Store - Much simpler than traditional CloudTrail!
resource "aws_cloudtrail_event_data_store" "iam_analyzer_store" {
  name = "${local.name_prefix}-event-data-store"

  # Multi-region disabled as requested
  multi_region_enabled = false
  
  # Organization events disabled as requested  
  organization_enabled = false
  
  # 90-day retention as requested
  retention_period = var.cloudtrail_retention_days
  
  # Termination protection for production use
  termination_protection_enabled = var.environment == "prod" ? true : false

  # Advanced event selectors for management events only
  advanced_event_selector {
    name = "Management events for IAM analysis"
    
    # Required: eventCategory field
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
    
    # Focus on key services for IAM analysis
    field_selector {
      field  = "eventSource" 
      equals = ["iam.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com", "lambda.amazonaws.com", "sts.amazonaws.com"]
    }
  }

  # Optional: Add data events for S3 if needed for analysis
  advanced_event_selector {
    name = "S3 data events"
    
    # Required: eventCategory field for data events
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    
    # Only include write operations to reduce noise
    field_selector {
      field  = "readOnly"
      equals = ["false"]
    }
  }

  tags = merge(local.common_tags, {
    Component = "cloudtrail-lake"
    Purpose   = "Direct SQL querying for IAM analysis"
    QueryType = "CloudTrail Lake SQL"
  })
}

# Example queries that can be run against CloudTrail Lake
# These don't create resources but show what queries your Lambda can run

locals {
  # Query to get IAM-related actions from last 90 days
  iam_usage_query = <<-EOQ
    SELECT 
      eventTime,
      userIdentity.arn as userArn,
      userIdentity.type as userType,
      userIdentity.userName as userName,
      eventSource,
      eventName,
      awsRegion,
      sourceIPAddress,
      errorCode,
      errorMessage
    FROM ${aws_cloudtrail_event_data_store.iam_analyzer_store.arn}
    WHERE 
      eventTime >= '${formatdate("YYYY-MM-DD", timeadd(timestamp(), "-${var.cloudtrail_retention_days * 24}h"))}'
      AND eventSource IN ('iam.amazonaws.com', 's3.amazonaws.com', 'ec2.amazonaws.com', 'lambda.amazonaws.com', 'sts.amazonaws.com')
      AND eventName NOT LIKE '%List%'
      AND eventName NOT LIKE '%Get%' 
      AND eventName NOT LIKE '%Describe%'
      AND errorCode IS NULL
    ORDER BY eventTime DESC
    LIMIT 10000
  EOQ

  # Query to analyze user action frequency for least privilege
  user_frequency_query = <<-EOQ
    SELECT 
      userIdentity.arn as userArn,
      userIdentity.userName as userName,
      eventSource,
      eventName,
      COUNT(*) as actionCount,
      MIN(eventTime) as firstUsed,
      MAX(eventTime) as lastUsed,
      CASE 
        WHEN COUNT(*) > 100 THEN 'High Usage'
        WHEN COUNT(*) > 10 THEN 'Medium Usage'
        ELSE 'Low Usage'
      END as usageLevel
    FROM ${aws_cloudtrail_event_data_store.iam_analyzer_store.arn}
    WHERE 
      eventTime >= '${formatdate("YYYY-MM-DD", timeadd(timestamp(), "-${var.cloudtrail_retention_days * 24}h"))}'
      AND userIdentity.type IN ('IAMUser', 'AssumedRole', 'Root')
      AND errorCode IS NULL
      AND eventName NOT LIKE '%List%'
      AND eventName NOT LIKE '%Get%'
      AND eventName NOT LIKE '%Describe%'
    GROUP BY 
      userIdentity.arn,
      userIdentity.userName,
      eventSource,
      eventName
    HAVING COUNT(*) >= 1
    ORDER BY actionCount DESC
  EOQ

  # Query to find unused permissions
  unused_permissions_query = <<-EOQ
    WITH user_actions AS (
      SELECT DISTINCT
        userIdentity.arn as userArn,
        CONCAT(eventSource, ':', eventName) as actionUsed
      FROM ${aws_cloudtrail_event_data_store.iam_analyzer_store.arn}
      WHERE 
        eventTime >= '${formatdate("YYYY-MM-DD", timeadd(timestamp(), "-${var.cloudtrail_retention_days * 24}h"))}'
        AND userIdentity.type IN ('IAMUser', 'AssumedRole')
        AND errorCode IS NULL
    )
    SELECT 
      userArn,
      COUNT(DISTINCT actionUsed) as uniqueActionsUsed,
      ARRAY_AGG(DISTINCT actionUsed) as actionsList
    FROM user_actions
    GROUP BY userArn
    ORDER BY uniqueActionsUsed ASC
  EOQ
}