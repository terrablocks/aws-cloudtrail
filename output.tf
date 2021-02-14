output "bucket" {
  value = aws_s3_bucket.trail.id
}

output "bucket_arn" {
  value = aws_s3_bucket.trail.arn
}

output "trail_kms_key_id" {
  value = var.create_trail_key ? join(",", aws_kms_key.trail.*.id) : null
}

output "trail_kms_key_alias" {
  value = var.create_trail_key ? join(",", aws_kms_alias.trail_kms.*.name) : null
}

output "cw_log_group_arn" {
  value = var.create_cw_resources ? join(",", aws_cloudwatch_log_group.trail.*.arn) : var.cw_log_group_arn
}

output "cw_log_group_role_arn" {
  value = var.create_cw_resources ? join(",", aws_iam_role.trail_cw.*.arn) : var.cw_log_group_role_arn
}

output "sns_topic_arn" {
  value = var.create_sns_resources ? join(",", aws_sns_topic.trail.*.arn) : var.sns_topic_name
}

output "trail" {
  value = aws_cloudtrail.trail.id
}

output "trail_arn" {
  value = aws_cloudtrail.trail.arn
}
