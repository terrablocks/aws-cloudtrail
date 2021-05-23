output "bucket" {
  value       = aws_s3_bucket.trail.id
  description = "Name of S3 bucket created"
}

output "bucket_arn" {
  value       = aws_s3_bucket.trail.arn
  description = "ARN of S3 bucket created"
}

output "trail_kms_key_id" {
  value       = var.create_trail_key ? join(",", aws_kms_key.trail.*.id) : null
  description = "ID of KMS key if created for CloudTrail"
}

output "trail_kms_key_alias" {
  value       = var.create_trail_key ? join(",", aws_kms_alias.trail_kms.*.name) : null
  description = "Alias of KMS key if created for CloudTrail"
}

output "cw_log_group_arn" {
  value       = var.create_cw_resources ? join(",", aws_cloudwatch_log_group.trail.*.arn) : var.cw_log_group_arn
  description = "ARN of CloudWatch logs group if associated with CloudTrail"
}

output "cw_log_group_role_arn" {
  value       = var.create_cw_resources ? join(",", aws_iam_role.trail_cw.*.arn) : var.cw_log_group_role_arn
  description = "ARN of IAM role if assocaited with CloudTrail for writing logs to CloudWatch log group"
}

output "sns_topic_arn" {
  value       = var.create_sns_resources ? join(",", aws_sns_topic.trail.*.arn) : var.sns_topic_name
  description = "ARN of SNS topic if created"
}

output "trail_name" {
  value       = aws_cloudtrail.trail.id
  description = "Name of the trail created"
}

output "trail_arn" {
  value       = aws_cloudtrail.trail.arn
  description = "ARN of the trail created"
}
