# -----------------------------------------------------------------------------
# S3 versioning policy
#
# Denies any change where S3 versioning is not enabled. Versioning makes it
# possible to recover deleted or overwritten objects.
# -----------------------------------------------------------------------------

package main

deny contains msg if {
	# Loop through every resource in the plan
	resource := input.resource_changes[_]

	# Only look at versioning resources
	resource.type == "aws_s3_bucket_versioning"

	# Check the planned versioning status
	config := resource.change.after.versioning_configuration[_]
	config.status != "Enabled"

	msg := sprintf("%s: versioning status must be 'Enabled', got '%s'", [resource.address, config.status])
}