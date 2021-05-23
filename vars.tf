variable "trail_name" {
  type        = string
  description = "Name for CloudTrail and other resources to be created alongwith"
}

variable "create_trail_key" {
  type        = bool
  default     = true
  description = "Whether to create new KMS key for encrypting logs delivered by CloudTrail"
}

variable "trail_kms_key_arn" {
  type        = string
  default     = null
  description = "ARN of existing KMS key for encrypting logs delivered by CloudTrail"
}

variable "trail_kms_key_policy" {
  type        = string
  default     = ""
  description = "Policy to associate with newly created KMS key. **Note:** Required ONLY if custom policy needs to be attached to newly created KMS key"
}

variable "trail_kms_key_deletion_window" {
  type        = number
  default     = 7
  description = "Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days"
}

variable "trail_enable_key_rotation" {
  type        = bool
  default     = true
  description = "Whether to rotate KMS key periodically automatically"
}

variable "bucket_key_prefix" {
  type        = string
  default     = ""
  description = "Prefix to attach to S3 object while storing logs"
}

variable "create_cw_resources" {
  type        = bool
  default     = false
  description = "Whether to create new CloudWatch log group and IAM role for storing CloudTrail logs"
}

variable "cw_retention_days" {
  type        = number
  default     = 0
  description = "Specifies the number of days you want to retain log events in the specified log group. **Possible values:** 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653, and 0. 0 means logs will be retained forever"
}

variable "cw_log_group_arn" {
  type        = string
  default     = null
  description = "ARN of existing CloudWatch logs group to associate with CloudTrail"
}

variable "cw_log_group_role_arn" {
  type        = string
  default     = null
  description = "ARN of IAM role to be used by CloudTrail for writing logs to CloudWatch log group"
}

variable "enable_multi_region_trail" {
  type        = bool
  default     = true
  description = "Whether to record API activities across all the regions"
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account"
}

variable "enable_logging" {
  type        = bool
  default     = true
  description = "Whether to enable CloudTrail logging"
}

variable "create_sns_resources" {
  type        = bool
  default     = false
  description = "Whether to create SNS topic to receive notification whenever logs are published"
}

variable "sns_topic_name" {
  type        = string
  default     = null
  description = "Name of existing SNS topic to associate with CloudTrail"
}

variable "sns_delivery_policy" {
  type        = string
  default     = null
  description = "SNS delivery policy"
}

variable "sns_kms_key" {
  type        = string
  default     = "alias/aws/sns"
  description = "ID/ARN/Alias of existing KMS key to associate with newly created SNS topic for encryption at rest"
}

variable "enable_log_file_validation" {
  type        = bool
  default     = true
  description = "Whether to include integrity hash for each log delivered"
}

variable "s3_force_destroy" {
  type        = bool
  default     = true
  description = "Empty bucket content before deleting the bucket"
}

variable "s3_kms_key" {
  type        = string
  default     = "alias/aws/s3"
  description = "ID/ARN/Alias of existing KMS key to associate with newly created S3 bucket for server-side encryption"
}

variable "s3_enable_versioning" {
  type        = bool
  default     = false
  description = "Whether to enable versioning feature for S3"
}

variable "s3_enable_mfa_delete" {
  type        = bool
  default     = false
  description = "Whether to enable MFA requirement while deleting object from S3"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Map of key-value pair to associate with resources"
}
