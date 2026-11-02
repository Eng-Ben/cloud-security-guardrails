# -----------------------------------------------------------------------------
# S3 encryption policy
#
# Denies any change where S3 default encryption does not use an approved
# algorithm. This ensures all objects are encrypted at rest.
# -----------------------------------------------------------------------------

package main

# Encryption algorithms that are allowed for S3 default encryption
allowed_sse_algorithms := {"AES256", "aws:kms", "aws:kms:dsse"}

deny contains msg if {
	# Loop through every resource in the plan
	resource := input.resource_changes[_]

	# Only look at encryption configuration resources
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"

	# Dig into the nested encryption settings
	rule := resource.change.after.rule[_]
	default_encryption := rule.apply_server_side_encryption_by_default[_]

	# Match if the algorithm is not in the allowed list
	not allowed_sse_algorithms[default_encryption.sse_algorithm]

	msg := sprintf("%s: sse_algorithm '%s' is not allowed", [resource.address, default_encryption.sse_algorithm])
}