# -----------------------------------------------------------------------------
# IAM wildcard policy
#
# Denies IAM policies that allow every action ("*"), and warns about
# policies that allow every action in one service (e.g. "s3:*").
# Enforces the principle of least privilege.
# -----------------------------------------------------------------------------

package main

# Terraform resource types that contain an IAM policy document
iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

# IAM allows both a single value and a list. This helper always returns a list.
as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# Find every allowed action in every IAM policy in the plan
allowed_actions contains [resource.address, action] if {
	resource := input.resource_changes[_]
	iam_policy_types[resource.type]

	# The policy is stored as a JSON string, so we turn it into an object
	document := json.unmarshal(resource.change.after.policy)

	statement := as_array(document.Statement)[_]
	statement.Effect == "Allow"
	action := as_array(statement.Action)[_]
}

# Deny: full access to everything
deny contains msg if {
	some [address, action] in allowed_actions
	action == "*"
	msg := sprintf("%s: IAM policy must not allow all actions ('*')", [address])
}

# Warn: full access to a whole service, e.g. "s3:*"
warn contains msg if {
	some [address, action] in allowed_actions
	action != "*"
	endswith(action, ":*")
	msg := sprintf("%s: IAM policy allows all actions in a service ('%s'). Consider limiting it.", [address, action])
}