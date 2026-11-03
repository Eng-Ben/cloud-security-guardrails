# -----------------------------------------------------------------------------
# Network ingress policy
#
# Denies security group rules that open SSH, RDP or all traffic to the whole
# internet, and warns about other ports open to the internet.
# Web ports 80 and 443 are allowed.
# -----------------------------------------------------------------------------

package main

# CIDR ranges that mean "the whole internet" (IPv4 and IPv6)
world_cidrs := {"0.0.0.0/0", "::/0"}

# Protocol values that mean "all traffic"
all_protocols := {"-1", "all"}

# Admin ports that must never be open to the internet
sensitive_ports := {22: "SSH", 3389: "RDP"}

# Ports that are normal to expose for a public website
web_ports := {80, 443}

# --- Collect every ingress rule open to the internet -------------------------
# AWS has three Terraform resources for ingress rules. We normalize all of them
# into the same shape: address, protocol, from_port, to_port.

# 1. Rules written inside aws_security_group
open_ingress contains entry if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	rule := resource.change.after.ingress[_]
	some key in ["cidr_blocks", "ipv6_cidr_blocks"]
	world_cidrs[rule[key][_]]
	entry := {
		"address": resource.address,
		"protocol": rule.protocol,
		"from_port": rule.from_port,
		"to_port": rule.to_port,
	}
}

# 2. Standalone aws_security_group_rule (only ingress, not egress)
open_ingress contains entry if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group_rule"
	rule := resource.change.after
	rule.type == "ingress"
	some key in ["cidr_blocks", "ipv6_cidr_blocks"]
	world_cidrs[rule[key][_]]
	entry := {
		"address": resource.address,
		"protocol": rule.protocol,
		"from_port": rule.from_port,
		"to_port": rule.to_port,
	}
}

# 3. The newer aws_vpc_security_group_ingress_rule
open_ingress contains entry if {
	resource := input.resource_changes[_]
	resource.type == "aws_vpc_security_group_ingress_rule"
	rule := resource.change.after
	some key in ["cidr_ipv4", "cidr_ipv6"]
	world_cidrs[rule[key]]
	entry := {
		"address": resource.address,
		"protocol": rule.ip_protocol,
		"from_port": object.get(rule, "from_port", 0),
		"to_port": object.get(rule, "to_port", 0),
	}
}

# --- Helpers -----------------------------------------------------------------

# True if the rule's port range includes SSH or RDP
exposes_sensitive_port(entry) if {
	some port, _ in sensitive_ports
	entry.from_port <= port
	port <= entry.to_port
}

# True if the rule opens exactly one web port (80 or 443)
is_web_port(entry) if {
	entry.from_port == entry.to_port
	web_ports[entry.from_port]
}

# --- Rules -------------------------------------------------------------------

# Deny: all traffic open to the internet
deny contains msg if {
	some entry in open_ingress
	all_protocols[entry.protocol]
	msg := sprintf("%s: ingress must not allow all traffic from the internet", [entry.address])
}

# Deny: SSH or RDP open to the internet
deny contains msg if {
	some entry in open_ingress
	not all_protocols[entry.protocol]
	some port, name in sensitive_ports
	entry.from_port <= port
	port <= entry.to_port
	msg := sprintf("%s: %s (port %d) must not be open to the internet", [entry.address, name, port])
}

# Warn: any other non-web port open to the internet
warn contains msg if {
	some entry in open_ingress
	not all_protocols[entry.protocol]
	not exposes_sensitive_port(entry)
	not is_web_port(entry)
	msg := sprintf("%s: ports %d-%d are open to the internet. Make sure this is intended.", [entry.address, entry.from_port, entry.to_port])
}