# -----------------------------------------------------------------------------
# Unit tests for the network ingress policy
# -----------------------------------------------------------------------------

package main

# --- Helpers: build fake plans ---------------------------------------------

ingress_rule(from, to, protocol, cidrs, ipv6_cidrs) := {
	"from_port": from,
	"to_port": to,
	"protocol": protocol,
	"cidr_blocks": cidrs,
	"ipv6_cidr_blocks": ipv6_cidrs,
}

sg_plan(rules) := {"resource_changes": [{
	"address": "aws_security_group.test",
	"type": "aws_security_group",
	"change": {"after": {"ingress": rules}},
}]}

# --- Allowed ----------------------------------------------------------------

test_ssh_from_internal_network_is_allowed if {
	plan := sg_plan([ingress_rule(22, 22, "tcp", ["10.0.0.0/16"], [])])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_https_from_internet_is_allowed if {
	plan := sg_plan([ingress_rule(443, 443, "tcp", ["0.0.0.0/0"], [])])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_egress_rule_is_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_security_group_rule.test",
		"type": "aws_security_group_rule",
		"change": {"after": {
			"type": "egress",
			"from_port": 0,
			"to_port": 0,
			"protocol": "-1",
			"cidr_blocks": ["0.0.0.0/0"],
		}},
	}]}
	count(deny) == 0 with input as plan
}

# --- Denied -----------------------------------------------------------------

test_ssh_from_internet_is_denied if {
	plan := sg_plan([ingress_rule(22, 22, "tcp", ["0.0.0.0/0"], [])])
	count(deny) == 1 with input as plan
}

test_ssh_from_ipv6_internet_is_denied if {
	plan := sg_plan([ingress_rule(22, 22, "tcp", [], ["::/0"])])
	count(deny) == 1 with input as plan
}

test_rdp_hidden_in_port_range_is_denied if {
	plan := sg_plan([ingress_rule(3000, 4000, "tcp", ["0.0.0.0/0"], [])])
	count(deny) == 1 with input as plan
}

test_all_traffic_from_internet_is_denied if {
	plan := sg_plan([ingress_rule(0, 0, "-1", ["0.0.0.0/0"], [])])
	count(deny) == 1 with input as plan
}

test_standalone_ingress_rule_is_denied if {
	plan := {"resource_changes": [{
		"address": "aws_security_group_rule.test",
		"type": "aws_security_group_rule",
		"change": {"after": {
			"type": "ingress",
			"from_port": 22,
			"to_port": 22,
			"protocol": "tcp",
			"cidr_blocks": ["0.0.0.0/0"],
		}},
	}]}
	count(deny) == 1 with input as plan
}

test_vpc_ingress_rule_is_denied if {
	plan := {"resource_changes": [{
		"address": "aws_vpc_security_group_ingress_rule.test",
		"type": "aws_vpc_security_group_ingress_rule",
		"change": {"after": {
			"from_port": 3389,
			"to_port": 3389,
			"ip_protocol": "tcp",
			"cidr_ipv4": "0.0.0.0/0",
		}},
	}]}
	count(deny) == 1 with input as plan
}

# --- Warned -----------------------------------------------------------------

test_other_port_from_internet_is_warned if {
	plan := sg_plan([ingress_rule(8080, 8080, "tcp", ["0.0.0.0/0"], [])])
	count(deny) == 0 with input as plan
	count(warn) == 1 with input as plan
}