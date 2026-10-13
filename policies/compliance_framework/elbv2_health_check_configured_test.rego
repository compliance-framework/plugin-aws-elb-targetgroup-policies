package compliance_framework.elbv2_health_check_configured_test

import data.compliance_framework.elbv2_health_check_configured as policy

well_configured_http_tg := {
	"schema_version": "v1",
	"source": "aws-elbv2",
	"account": {"account_id": "123456789012"},
	"region": {"name": "us-east-1"},
	"resource": {
		"id": "targetgroup/my-tg/abc123",
		"arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abc123",
		"type": "target-group",
	},
	"config": {
		"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abc123",
		"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc",
		"protocol": "HTTP",
		"port": 80,
		"health_check_protocol": "HTTP",
		"health_check_path": "/healthz",
		"healthy_threshold_count": 3,
		"unhealthy_threshold_count": 3,
	},
}

test_well_configured_http_target_group_passes if {
	count(policy.violation) == 0 with input as well_configured_http_tg
}

test_low_healthy_threshold_fails if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"healthy_threshold_count": 1})},
	])

	count(policy.violation) >= 1 with input as inp
	policy.violation[{"id": "healthy_threshold_too_low"}] with input as inp
}

test_min_healthy_threshold_passes if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"healthy_threshold_count": 2})},
	])

	count(policy.violation) == 0 with input as inp
}

test_http_health_check_path_missing_fails_when_required if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"health_check_path": ""})},
	])

	count(policy.violation) >= 1 with input as inp
	policy.violation[{"id": "health_check_path_missing"}] with input as inp
}

test_http_health_check_path_missing_passes_when_not_required if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"health_check_path": ""})},
	])

	count(policy.violation) == 0 with input as inp with data.require_health_check_path_for_http as false # regal ignore:unresolved-reference
}

test_missing_health_check_protocol_fails if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"health_check_protocol": ""})},
	])

	count(policy.violation) >= 1 with input as inp
	policy.violation[{"id": "health_check_protocol_missing"}] with input as inp
}

test_high_unhealthy_threshold_fails if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"unhealthy_threshold_count": 11})},
	])

	count(policy.violation) >= 1 with input as inp
	policy.violation[{"id": "unhealthy_threshold_too_high"}] with input as inp
}

test_max_unhealthy_threshold_passes if {
	inp := object.union_n([
		well_configured_http_tg,
		{"config": object.union(well_configured_http_tg.config, {"unhealthy_threshold_count": 10})},
	])

	count(policy.violation) == 0 with input as inp
}

test_missing_threshold_fails_with_missing_threshold_violation if {
	inp := object.union(object.remove(well_configured_http_tg, {"config"}), {"config": object.remove(well_configured_http_tg.config, {"healthy_threshold_count"})})

	count(policy.violation) == 1 with input as inp
	policy.violation[{"id": "health_check_thresholds_missing"}] with input as inp
}

test_non_target_group_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "listener-1"}}

	count(policy.violation) == 0 with input as inp
	policy.skip_reason with input as inp
}
