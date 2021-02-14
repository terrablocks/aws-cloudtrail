# Enables CloudTrail

This terraform module will deploy the following services:
- CloudWatch
  - Log Group
- S3
- IAM Role & Policy
- SNS Topic
- KMS
- CloudTrail

## Licence:
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

MIT Licence. See [Licence](LICENCE) for full details.

# Usage Instructions:
## Example:
```terraform
module "vpc" {
  source = "github.com/terrablocks/aws-cloudtrail.git"

  trail_name = "all-regions"
}
```


## Variables
| Parameter             | Type    | Description                                                               | Default                      | Required |
|-----------------------|---------|---------------------------------------------------------------------------|------------------------------|----------|
| trail_name            | string  | Name for CloudTrail and other resources to be created alongwith                                                        |                  | Y        |
| create_trail_key      | boolena  | Whether to create new KMS key for encrypting logs delivered by CloudTrail                        | true                             | N        |
| trail_kms_key_arn     | strinf    | ARN of existing KMS key for encrypting logs delivered by CloudTrail         |  | N        |
| trail_kms_key_policy       | string  | Policy to associate with newly created KMS key. **Note:** Required ONLY if custom policy needs to be attached to newly created KMS key                |    | N        |
| trail_kms_key_deletion_window  | number  | Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days              | 7     | N        |
| trail_enable_key_rotation  | boolean | Whether to rotate KMS key periodically automatically        | false     | N        |
| bucket_key_prefix      | string | Prefix to attach to S3 object while storing logs          |     | N        |
| create_cw_resources | boolean  | Whether to create new CloudWatch log group and IAM role for storing CloudTrail logs    | false   | N        |
| cw_log_group_arn          | string | ARN of existing CloudWatch logs group to associate with CloudTrail       |       | N        |
| cw_log_group_role_arn   | string  | ARN of IAM role to be used by CloudTrail for writing logs to CloudWatch log group        |     | N        |
| enable_multi_region_trail   | boolean  | Whether to record API activities across all the regions        | true          | N        |
| is_organization_trail   | boolean  | Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account        | false          | N        |
| enable_logging   | boolean  | Whether to enable CloudTrail logging        | true          | N        |
| create_sns_resources   | boolean  | Whether to create SNS topic to receive notification whenever logs are published        | false          | N        |
| sns_topic_name   | string  | Name of existing SNS topic to associate with CloudTrail        |      | N        |
| sns_delivery_policy   | string  | SNS delivery policy     |    | N        |
| sns_kms_key_id   | string  | ID/ARN/Alias of existing KMS key to associate with newly created SNS topic for encryption at rest     | alias/aws/sns   | N        |
| enable_log_file_validation   | boolean  | Whether to include integrity hash for each log delivered      | true          | N        |
| s3_kms_key_id   | string  | ID/ARN/Alias of existing KMS key to associate with newly created S3 bucket for server-side encryption      | alias/aws/sns          | N        |
| tags   | map  | Map of key-value pair to associate with resources             | {}     | N        |


## Outputs
| Parameter            | Type   | Description                                                      |
|----------------------|--------|------------------------------------------------------------------|
| bucket               | string | Name of S3 bucket created                                                |
| bucket_arn           | string | ARN of S3 bucket created                                                |
| trail_kms_key_id     | string   | ID of KMS key if created for CloudTrail                                   |
| trail_kms_key_alias  | string   | Alias of KMS key if created for CloudTrail                           |
| cw_log_group_arn    | string   | ARN of CloudWatch logs group if associated with CloudTrail            |
| cw_log_group_role_arn | string   | ARN of IAM role if assocaited with CloudTrail for writing logs to CloudWatch log group         |
| sns_topic_arn        | string | ARN of SNS topic if created                                        |
| trail          | string | Name of the trail created                     |
| trail_arn          | string | ARN of the trail created           |

## Deployment
- `terraform init` - download plugins required to deploy resources
- `terraform plan` - get detailed view of resources that will be created, deleted or replaced
- `terraform apply -auto-approve` - deploy the template without confirmation (non-interactive mode)
- `terraform destroy -auto-approve` - terminate all the resources created using this template without confirmation (non-interactive mode)
