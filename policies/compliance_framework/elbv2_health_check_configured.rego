package compliance_framework.elbv2_health_check_configured

# METADATA
# title: ELBv2 target group health checks are configured
# description: Checks whether a target group has health checks with sane thresholds.
# custom:
#   metric_ids:
#     - ELB_TARGET_HEALTH
#   controls:
#     - ctrl-a1-1-009
#     - ctrl-a1-2-007
risk_templates := [{
	"name": "Target group health checks misconfigured",
	"title": "Weak Health Checks Let a Load Balancer Route to Unhealthy Targets",
	"statement": "Missing or poorly tuned health checks prevent the load balancer from reliably detecting failed targets, so traffic is routed to instances that cannot serve it. This degrades availability and can mask outages until users are affected.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-754",
		"title": "Improper Check for Unusual or Exceptional Conditions",
		"url": "https://cwe.mitre.org/data/definitions/754.html",
	}],
	"remediation": {
		"title": "Configure health checks with sane thresholds",
		"description": "Set a health-check protocol and, for HTTP/HTTPS, a specific path. Tune healthy and unhealthy threshold counts within policy bounds so unhealthy targets are detected and drained promptly.",
		"tasks": [
			{"title": "Set the health-check protocol and, for HTTP/HTTPS, a specific path"},
			{"title": "Tune healthy and unhealthy threshold counts within approved bounds"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
tg_arn := object.get(config, "target_group_arn", "unknown")
hc_protocol := upper(object.get(config, "health_check_protocol", ""))
hc_path := object.get(config, "health_check_path", "")
healthy := object.get(config, "healthy_threshold_count", null)
unhealthy := object.get(config, "unhealthy_threshold_count", null)
min_healthy := data.min_healthy_threshold
max_unhealthy := data.max_unhealthy_threshold
require_path := data.require_health_check_path_for_http

skip_reason := sprintf("Resource type %q is not a target group; this policy only applies to target-group records.", [resource_type]) if {
	not resource_type == "target-group"
}

title := sprintf("Validate health check configuration for %s", [tg_arn])

description := sprintf("Target group %s health_check_protocol=%q healthy=%v unhealthy=%v.", [tg_arn, hc_protocol, healthy, unhealthy])

healthy_threshold_present if {
	healthy != null
}

unhealthy_threshold_present if {
	unhealthy != null
}

thresholds_missing if {
	not healthy_threshold_present
}

thresholds_missing if {
	not unhealthy_threshold_present
}

violation[{"id": "health_check_protocol_missing"}] if {
	resource_type == "target-group"
	hc_protocol == ""
}

violation[{"id": "healthy_threshold_too_low"}] if {
	resource_type == "target-group"
	healthy_threshold_present
	healthy < min_healthy
}

violation[{"id": "unhealthy_threshold_too_high"}] if {
	resource_type == "target-group"
	unhealthy_threshold_present
	unhealthy > max_unhealthy
}

violation[{"id": "health_check_thresholds_missing"}] if {
	resource_type == "target-group"
	thresholds_missing
}

violation[{"id": "health_check_path_missing"}] if {
	resource_type == "target-group"
	require_path == true
	hc_protocol in {"HTTP", "HTTPS"}
	hc_path == ""
}
