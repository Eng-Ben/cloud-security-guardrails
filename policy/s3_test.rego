# -----------------------------------------------------------------------------
# Unit tests for the S3 policies
#
# Each test builds a small fake Terraform plan and checks that the policies
# allow the secure version and deny the insecure version.
# Run with: conftest verify --policy policy
# -----------------------------------------------------------------------------

package main

# --- Helpers: build fake plans --------------------------------------------

public_access_plan(value) := {"resource_changes": [{
	"address": "aws_s3_bucket_public_access_block.test",
	"type": "aws_s3_bucket_public_access_block",
	"change": {"after": {
		"block_public_acls": value,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}},
}]}

versioning_plan(status) := {"resource_changes": [{
	"address": "aws_s3_bucket_versioning.test",
	"type": "aws_s3_bucket_versioning",
	"change": {"after": {"versioning_configuration": [{"status": status}]}},
}]}

encryption_plan(algorithm) := {"resource_changes": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.test",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{
		"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm}],
	}]}},
}]}

# --- Public access block --------------------------------------------------

test_public_access_block_enabled_is_allowed if {
	count(deny) == 0 with input as public_access_plan(true)
}

test_public_access_block_disabled_is_denied if {
	count(deny) == 1 with input as public_access_plan(false)
}

# --- Versioning -----------------------------------------------------------

test_versioning_enabled_is_allowed if {
	count(deny) == 0 with input as versioning_plan("Enabled")
}

test_versioning_suspended_is_denied if {
	count(deny) == 1 with input as versioning_plan("Suspended")
}

# --- Encryption -----------------------------------------------------------

test_encryption_aes256_is_allowed if {
	count(deny) == 0 with input as encryption_plan("AES256")
}

test_encryption_kms_is_allowed if {
	count(deny) == 0 with input as encryption_plan("aws:kms")
}

test_encryption_unknown_algorithm_is_denied if {
	count(deny) == 1 with input as encryption_plan("NONE")
}