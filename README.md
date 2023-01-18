# Enable CloudTrail for your AWS account

![License](https://img.shields.io/github/license/terrablocks/aws-cloudtrail?style=for-the-badge) ![Tests](https://img.shields.io/github/actions/workflow/status/terrablocks/aws-cloudtrail/tests.yml?branch=main&label=Test&style=for-the-badge) ![Checkov](https://img.shields.io/github/actions/workflow/status/terrablocks/aws-cloudtrail/checkov.yml?branch=main&label=Checkov&style=for-the-badge) ![Commit](https://img.shields.io/github/last-commit/terrablocks/aws-cloudtrail?style=for-the-badge) ![Release](https://img.shields.io/github/v/release/terrablocks/aws-cloudtrail?style=for-the-badge)

This terraform module will deploy the following services:
- CloudTrail
- S3
- IAM Role & Policy
- CloudWatch Log Group (Optional)
- SNS Topic
- KMS

# Usage Instructions
## Example
```terraform
module "trail" {
  source = "github.com/terrablocks/aws-cloudtrail.git"

  trail_name = "all-regions"
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.15 |
| aws | >= 4.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| trail_name | Name for CloudTrail and other resources to be created alongwith | `string` | n/a | yes |
| create_trail_key | Whether to create new KMS key for encrypting logs delivered by CloudTrail | `bool` | `true` | no |
| trail_kms_key_arn | ARN of existing KMS key for encrypting logs delivered by CloudTrail | `string` | `null` | no |
| trail_kms_key_policy | Policy to associate with newly created KMS key. **Note:** Required ONLY if custom policy needs to be attached to newly created KMS key | `string` | `""` | no |
| trail_kms_key_deletion_window | Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days | `number` | `7` | no |
| trail_enable_key_rotation | Whether to rotate KMS key periodically automatically | `bool` | `true` | no |
| bucket_key_prefix | Prefix to attach to S3 object while storing logs | `string` | `""` | no |
| create_cw_resources | Whether to create new CloudWatch log group and IAM role for storing CloudTrail logs | `bool` | `false` | no |
| cw_retention_days | Specifies the number of days you want to retain log events in the specified log group. **Possible values:** 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653, and 0. 0 means logs will be retained forever | `number` | `0` | no |
| cw_log_group_arn | ARN of existing CloudWatch logs group to associate with CloudTrail | `string` | `null` | no |
| cw_log_group_role_arn | ARN of IAM role to be used by CloudTrail for writing logs to CloudWatch log group | `string` | `null` | no |
| enable_multi_region_trail | Whether to record API activities across all the regions | `bool` | `true` | no |
| is_organization_trail | Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account | `bool` | `false` | no |
| enable_logging | Whether to enable CloudTrail logging | `bool` | `true` | no |
| create_sns_resources | Whether to create SNS topic to receive notification whenever logs are published | `bool` | `false` | no |
| sns_topic_name | Name of existing SNS topic to associate with CloudTrail | `string` | `null` | no |
| sns_delivery_policy | SNS delivery policy | `string` | `null` | no |
| sns_kms_key | ID/ARN/Alias of existing KMS key to associate with newly created SNS topic for encryption at rest | `string` | `"alias/aws/sns"` | no |
| enable_log_file_validation | Whether to include integrity hash for each log delivered | `bool` | `true` | no |
| s3_force_destroy | Empty bucket content before deleting the bucket | `bool` | `true` | no |
| s3_kms_key | ID/ARN/Alias of existing KMS key to associate with newly created S3 bucket for server-side encryption | `string` | `"alias/aws/s3"` | no |
| s3_versioning_status | The versioning status of the S3 bucket. Valid values: `Enabled`, `Suspended` or `Disabled`. **Note:** Disabled can only be used if the versioning was never enabled on the bucket | `string` | `"Disabled"` | no |
| s3_enable_mfa_delete | Whether to enable MFA requirement while deleting object from S3 | `bool` | `false` | no |
| tags | Map of key-value pair to associate with resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| bucket | Name of S3 bucket created |
| bucket_arn | ARN of S3 bucket created |
| trail_kms_key_id | ID of KMS key if created for CloudTrail |
| trail_kms_key_alias | Alias of KMS key if created for CloudTrail |
| cw_log_group_arn | ARN of CloudWatch logs group if associated with CloudTrail |
| cw_log_group_role_arn | ARN of IAM role if assocaited with CloudTrail for writing logs to CloudWatch log group |
| sns_topic_arn | ARN of SNS topic if created |
| trail_name | Name of the trail created |
| trail_arn | ARN of the trail created |
