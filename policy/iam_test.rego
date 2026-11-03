# -----------------------------------------------------------------------------
# Unit tests for the IAM wildcard policy
# -----------------------------------------------------------------------------

package main

# --- Helper: build a fake plan with one IAM policy ------------------------

iam_plan(statement) := {"resource_changes": [{
	"address": "aws_iam_policy.test",
	"type": "aws_iam_policy",
	"change": {"after": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": statement,
	})}},
}]}

# --- Allowed --------------------------------------------------------------

test_iam_specific_action_is_allowed if {
	plan := iam_plan([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_iam_deny_statement_with_wildcard_is_allowed if {
	plan := iam_plan([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
	count(deny) == 0 with input as plan
}

# --- Denied ---------------------------------------------------------------

test_iam_wildcard_action_is_denied if {
	plan := iam_plan([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
	count(deny) == 1 with input as plan
}

test_iam_wildcard_hidden_in_list_is_denied if {
	plan := iam_plan([{"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": "*"}])
	count(deny) == 1 with input as plan
}

test_iam_single_statement_object_is_denied if {
	plan := iam_plan({"Effect": "Allow", "Action": "*", "Resource": "*"})
	count(deny) == 1 with input as plan
}

# --- Warned ---------------------------------------------------------------

test_iam_service_wildcard_is_warned if {
	plan := iam_plan([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
	count(deny) == 0 with input as plan
	count(warn) == 1 with input as plan
}