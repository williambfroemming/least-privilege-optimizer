resource "aws_cloudtrail" "ucb_capstone_trail" {
  name                          = "ucb-capstone-cloudtrail"
  s3_bucket_name                = "ucb-capstone-aws-cloudtrail-logs"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  lifecycle {
    ignore_changes = [advanced_event_selector, kms_key_id]
  }
}
