# -----------------------------------------------------------------------------
# S3 public access policy
#
# Checks a Terraform plan (JSON) and denies any change where an
# S3 public access block does not have all four settings enabled.
# -----------------------------------------------------------------------------

package main

# The four settings that together block all public access to a bucket.
public_access_settings := [
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
]

# Deny if any of the settings above is not true in the planned configuration.
deny contains msg if {
	# Loop through every resource in the plan
	resource := input.resource_changes[_]

	# Only look at public access block resources
	resource.type == "aws_s3_bucket_public_access_block"

	# Check each setting, and match if it is not true
	some setting in public_access_settings
	resource.change.after[setting] != true

	msg := sprintf("%s: %s must be set to true", [resource.address, setting])
}