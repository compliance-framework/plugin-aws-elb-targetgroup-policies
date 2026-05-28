package compliance_framework.elbv2_multi_az_redundancy

# METADATA
# title: ELBv2 load balancer spans multiple availability zones
# description: Checks whether a load balancer is deployed across the required number of AZs.
# custom:
#   metric_ids:
#     - ELB_TARGET_HEALTH
#   controls:
#     - ctrl-a1-1-009
#     - ctrl-a1-2-006
#     - ctrl-a1-2-007
risk_templates := [{
	"name": "Load balancer not deployed across multiple availability zones",
	"title": "Single-AZ Load Balancer Creates an Availability Single Point of Failure",
	"statement": "A load balancer confined to one availability zone cannot survive the loss of that zone. An AZ outage takes the entire front-end offline, defeating the redundancy the load balancer is meant to provide and breaching availability commitments.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1188",
		"title": "Insecure Default Initialization of Resource",
		"url": "https://cwe.mitre.org/data/definitions/1188.html",
	}],
	"remediation": {
		"title": "Deploy load balancers across multiple availability zones",
		"description": "Attach the load balancer to subnets in at least the required number of availability zones so traffic can fail over when one zone is impaired.",
		"tasks": [
			{"title": "Add subnets from additional availability zones to the load balancer"},
			{"title": "Confirm targets exist and are healthy in each enabled zone"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", "unknown")
azs := object.get(config, "availability_zones", [])
minimum_azs := data.minimum_availability_zones

skip_reason := sprintf("Resource type %q is not a load balancer; this policy only applies to loadbalancer records.", [resource_type]) if {
	not resource_type == "loadbalancer"
}

title := sprintf("Validate ELBv2 multi-AZ redundancy for %s", [resource_id])
description := sprintf("Load balancer %s is deployed across %d AZs; minimum required is %d.", [resource_id, count(azs), minimum_azs])

violation contains {"id": "insufficient_availability_zones"} if {
	resource_type == "loadbalancer"
	count(azs) < minimum_azs
}
