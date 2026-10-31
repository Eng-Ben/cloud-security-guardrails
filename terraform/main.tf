# -----------------------------------------------------------------------------
# Terraform and provider configuration
# -----------------------------------------------------------------------------

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0" # Any 6.x version, but not 7.0
    }
  }
}

# All resources are created in the Stockholm region.
provider "aws" {
  region = "eu-north-1"
}

# -----------------------------------------------------------------------------
# S3 bucket
# -----------------------------------------------------------------------------

# bucket_prefix lets AWS generate a globally unique bucket name.
resource "aws_s3_bucket" "security_lab" {
  bucket_prefix = "cloud-security-lab-"
}

# -----------------------------------------------------------------------------
# Security controls for the bucket
# -----------------------------------------------------------------------------

# Block every form of public access. Misconfigured public buckets
# are one of the most common causes of cloud data leaks.
resource "aws_s3_bucket_public_access_block" "security_lab" {
  bucket = aws_s3_bucket.security_lab.id

  block_public_acls       = true # Reject new public ACLs
  block_public_policy     = true # Reject bucket policies that grant public access
  ignore_public_acls      = true # Ignore any existing public ACLs
  restrict_public_buckets = true # Restrict access if a public policy exists
}

# Encrypt all objects at rest using S3-managed keys.
resource "aws_s3_bucket_server_side_encryption_configuration" "security_lab" {
  bucket = aws_s3_bucket.security_lab.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Keep previous versions of objects, so deleted or overwritten
# data (e.g. from mistakes or ransomware) can be recovered.
resource "aws_s3_bucket_versioning" "security_lab" {
  bucket = aws_s3_bucket.security_lab.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Disable ACLs so the bucket owner controls all objects
# and access is managed only through IAM and bucket policies.
resource "aws_s3_bucket_ownership_controls" "security_lab" {
  bucket = aws_s3_bucket.security_lab.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}