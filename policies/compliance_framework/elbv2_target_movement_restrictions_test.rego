package compliance_framework.elbv2_target_movement_restrictions_test

import data.compliance_framework.elbv2_target_movement_restrictions as policy

http_target_group := {
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

test_default_empty_approval_lists_pass if {
	count(policy.violation) == 0 with input as http_target_group
}

test_approved_protocol_and_port_pass if {
	count(policy.violation) == 0 with input as http_target_group with data.approved_target_protocols as ["HTTP", "HTTPS"] with data.approved_target_ports as [80, 443]
}

test_target_protocol_not_approved if {
	count(policy.violation) == 1 with input as http_target_group with data.approved_target_protocols as ["HTTPS"]
	policy.violation[{"id": "target_protocol_not_approved"}] with input as http_target_group with data.approved_target_protocols as ["HTTPS"]
}

test_target_port_not_approved if {
	count(policy.violation) == 1 with input as http_target_group with data.approved_target_ports as [443]
	policy.violation[{"id": "target_port_not_approved"}] with input as http_target_group with data.approved_target_ports as [443]
}

test_approved_protocol_data_is_case_insensitive if {
	count(policy.violation) == 0 with input as http_target_group with data.approved_target_protocols as ["http"]
}

test_non_target_group_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "listener-1"}}

	count(policy.violation) == 0 with input as inp with data.approved_target_protocols as ["HTTPS"] with data.approved_target_ports as [443]
	policy.skip_reason with input as inp
}
