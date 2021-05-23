data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS key for s3 sse encryption
data "aws_kms_key" "trail_s3" {
  key_id = var.s3_kms_key
}

# KMS key for sns topic rest-side encryption
data "aws_kms_key" "trail_sns" {
  key_id = var.sns_kms_key
}

# S3 bucket for storing cloudtrail logs
resource "aws_s3_bucket" "trail" {
  # checkov:skip=CKV_AWS_19: Default SSE is always in place
  # checkov:skip=CKV_AWS_18: Access logging not required
  # checkov:skip=CKV_AWS_144: CRR not required
  # checkov:skip=CKV_AWS_145: Using KMS key for SSE depends on user
  # checkov:skip=CKV_AWS_52: Enabling MFA delete depends on user
  # checkov:skip=CKV_AWS_21: Enabling versioning depends on user
  bucket        = "${var.trail_name}-cloudtrail"
  force_destroy = var.s3_force_destroy
  acl           = "private"

  versioning {
    enabled    = var.s3_enable_versioning
    mfa_delete = var.s3_enable_mfa_delete
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = var.s3_kms_key == "alias/aws/s3" ? null : data.aws_kms_key.trail_s3.id
        sse_algorithm     = var.s3_kms_key == "alias/aws/s3" ? "AES256" : "aws:kms"
      }
    }
  }

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.trail_name}-cloudtrail"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.trail_name}-cloudtrail/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
          "Sid": "AllowSSLRequestsOnly",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${var.trail_name}-cloudtrail",
            "arn:aws:s3:::${var.trail_name}-cloudtrail/*"
          ],
          "Condition": {
            "Bool": {
              "aws:SecureTransport": "false"
            }
          }
        }
    ]
}
POLICY

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch log group for storing CloudTrail logs
resource "aws_cloudwatch_log_group" "trail" {
  count             = var.create_cw_resources ? 1 : 0
  name              = "${var.trail_name}-cloudtrail"
  retention_in_days = var.cw_retention_days
  kms_key_id        = var.create_trail_key ? join(",", aws_kms_key.trail.*.arn) : var.trail_kms_key_arn
  tags              = var.tags
}

# IAM role for giving permission to CloudTrail to write logs to CloudWatch
resource "aws_iam_role" "trail_cw" {
  count = var.create_cw_resources ? 1 : 0
  name  = "${var.trail_name}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      },
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "trail_cw" {
  count = var.create_cw_resources ? 1 : 0
  name  = "${var.trail_name}-cloudtrail-cw-role-policy"
  role  = join(",", aws_iam_role.trail_cw.*.id)

  policy = <<POLICY
  {
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "AWSCloudTrailCreateLogStream2014110",
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "${join(",", aws_cloudwatch_log_group.trail.*.arn)}:log-stream:*"
        ]
      }
    ]
  }
POLICY
}

# SNS topic to trigger every time a log file is published
resource "aws_sns_topic" "trail" {
  count             = var.create_sns_resources ? 1 : 0
  name              = "${var.trail_name}-cloudtrail"
  delivery_policy   = var.sns_delivery_policy
  kms_master_key_id = data.aws_kms_key.trail_sns.id
  tags              = var.tags
}

resource "aws_sns_topic_policy" "trail_sns" {
  count  = var.create_sns_resources ? 1 : 0
  arn    = join(",", aws_sns_topic.trail.*.arn)
  policy = data.aws_iam_policy_document.trail_sns.json
}

data "aws_iam_policy_document" "trail_sns" {
  statement {
    actions = [
      "SNS:Publish"
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id
      ]
    }

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = [
      join(",", aws_sns_topic.trail.*.arn)
    ]
  }
}

# KMS key for encrypting CloudTrail logs
resource "aws_kms_key" "trail" {
  # checkov:skip=CKV_AWS_7: Key rotation is by default enabled but can be turned off by user
  count                    = var.create_trail_key ? 1 : 0
  description              = "Key for encrypting CloudTrail logs"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = var.trail_kms_key_policy == "" ? data.aws_iam_policy_document.trail_kms.json : var.trail_kms_key_policy
  deletion_window_in_days  = var.trail_kms_key_deletion_window
  enable_key_rotation      = var.trail_enable_key_rotation
  tags                     = var.tags
}

resource "aws_kms_alias" "trail_kms" {
  name          = "alias/${var.trail_name}-cloudtrail"
  target_key_id = join(",", aws_kms_key.trail.*.key_id)
}

data "aws_iam_policy_document" "trail_kms" {
  # checkov:skip=CKV_AWS_109: Condition present for permission management
  # checkov:skip=CKV_AWS_111: Condition present for write access
  statement {
    actions = [
      "kms:GenerateDataKey*"
    ]

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"

      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}/*"
      ]
    }

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"

      values = [
        "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.trail_name}-cloudtrail"
      ]
    }

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "kms:*"
    ]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    resources = [
      "*"
    ]
  }
}

resource "aws_cloudtrail" "trail" {
  # checkov:skip=CKV_AWS_36: By default log file validation is switched on
  # checkov:skip=CKV_AWS_67: By default multi-regional trail is created
  enable_logging                = var.enable_logging
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  s3_key_prefix                 = var.bucket_key_prefix
  include_global_service_events = true
  cloud_watch_logs_group_arn    = var.create_cw_resources ? join(",", aws_cloudwatch_log_group.trail.*.arn) : var.cw_log_group_arn
  cloud_watch_logs_role_arn     = var.create_cw_resources ? join(",", aws_iam_role.trail_cw.*.arn) : var.cw_log_group_role_arn
  is_multi_region_trail         = var.enable_multi_region_trail
  is_organization_trail         = var.is_organization_trail
  sns_topic_name                = var.create_sns_resources ? join(",", aws_sns_topic.trail.*.arn) : var.sns_topic_name
  enable_log_file_validation    = var.enable_log_file_validation
  kms_key_id                    = var.create_trail_key ? join(", ", aws_kms_key.trail.*.arn) : var.trail_kms_key_arn

  event_selector {
    read_write_type = "All"
  }

  tags = var.tags
}
