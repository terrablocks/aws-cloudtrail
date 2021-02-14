variable "trail_name" {}

variable "create_trail_key" {
  default = true
}

variable "trail_kms_key_arn" {
  default = null
}

variable "trail_kms_key_policy" {
  default = ""
}

variable "trail_kms_key_deletion_window" {
  default = 7
}

variable "trail_enable_key_rotation" {
  default = false
}

variable "bucket_key_prefix" {
  default = ""
}

variable "create_cw_resources" {
  default = false
}

variable "cw_log_group_arn" {
  default = null
}

variable "cw_log_group_role_arn" {
  default = null
}

variable "enable_multi_region_trail" {
  default = true
}

variable "is_organization_trail" {
  default = false
}

variable "enable_logging" {
  default = true
}

variable "create_sns_resources" {
  default = false
}

variable "sns_topic_name" {
  default = null
}

variable "sns_delivery_policy" {
  default = null
}

variable "sns_kms_key_id" {
  default = "alias/aws/sns"
}

variable "enable_log_file_validation" {
  default = true
}

variable "s3_kms_key_id" {
  default = "alias/aws/s3"
}

variable "tags" {
  type    = map(any)
  default = {}
}
