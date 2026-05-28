package compliance_framework.elbv2_target_movement_restrictions

# METADATA
# title: ELBv2 target group movement is restricted to approved protocols and ports
# description: Checks whether a target group forwards traffic only over approved protocols and ports.
# custom:
#   controls:
#     - ctrl-cc6-7-002
#     - ctrl-cc6-7-005
risk_templates := [{
	"name": "Target group movement restrictions bypassed",
	"title": "Unapproved Target Protocols or Ports Can Expose Uncontrolled Traffic Paths",
	"statement": "A target group that forwards traffic over unapproved protocols or ports can bypass expected network governance and encryption controls. If the protocol is cleartext, backend traffic may be observable or modified in transit; even encrypted protocols can create unmanaged movement paths when they are outside the approved inventory.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-319",
		"title": "Cleartext Transmission of Sensitive Information",
		"url": "https://cwe.mitre.org/data/definitions/319.html",
	}],
	"remediation": {
		"title": "Restrict target group protocols and ports",
		"description": "Configure target groups to use only approved backend protocols and ports. Update policy data when an exception is reviewed and accepted.",
		"tasks": [
			{"title": "Change the target group protocol to an approved value"},
			{"title": "Change the target group port to an approved value"},
			{"title": "Review and document exceptions before adding them to policy data"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
tg_arn := object.get(config, "target_group_arn", "unknown")
protocol := upper(object.get(config, "protocol", ""))
port := object.get(config, "port", 0)
approved_protocols := [upper(p) | p := data.approved_target_protocols[_]]
approved_ports := data.approved_target_ports

skip_reason := sprintf("Resource type %q is not a target group; this policy only applies to target-group records.", [resource_type]) if {
	not resource_type == "target-group"
}

title := sprintf("Validate target movement restrictions for %s", [tg_arn])

description := sprintf("Target group %s protocol=%q port=%d.", [tg_arn, protocol, port])

approved_protocol if {
	protocol in approved_protocols
}

approved_port if {
	port in approved_ports
}

violation[{"id": "target_protocol_not_approved"}] if {
	resource_type == "target-group"
	count(approved_protocols) > 0
	not approved_protocol
}

violation[{"id": "target_port_not_approved"}] if {
	resource_type == "target-group"
	count(approved_ports) > 0
	not approved_port
}
