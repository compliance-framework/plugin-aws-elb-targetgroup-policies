package compliance_framework.elbv2_multi_az_redundancy_test

test_multi_az_ok if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "config": {"availability_zones": ["a", "b"]}}
	count(data.compliance_framework.elbv2_multi_az_redundancy.violation) == 0 with input as inp
}

test_single_az_violation if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "config": {"availability_zones": ["a"]}}
	count(data.compliance_framework.elbv2_multi_az_redundancy.violation) == 1 with input as inp
}

test_non_default_minimum_azs if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "config": {"availability_zones": ["a", "b"]}}
	count(data.compliance_framework.elbv2_multi_az_redundancy.violation) == 1 with input as inp with data.minimum_availability_zones as 3
}

test_non_loadbalancer_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "l-1"}}
	count(data.compliance_framework.elbv2_multi_az_redundancy.violation) == 0 with input as inp
	data.compliance_framework.elbv2_multi_az_redundancy.skip_reason with input as inp
}
