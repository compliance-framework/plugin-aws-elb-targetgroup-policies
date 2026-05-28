# AWS ELBv2 load balancer policies

Standalone OPA/Rego policy bundle for load balancer evidence emitted by the `aws-elbv2` Compliance Framework plugin.

## Input schema

Each policy evaluates documents where `input.resource.type == "loadbalancer"`.

```json
{
  "schema_version": "v1",
  "source": "aws-elbv2",
  "account": { "account_id": "123456789012", "tags": {"environment": "prod"} },
  "region": { "name": "us-east-1" },
  "resource": {
    "id": "app/my-alb/abc123",
    "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
    "type": "loadbalancer"
  },
  "config": {
    "load_balancer_arn": "arn:aws:elasticloadbalancing:...:loadbalancer/app/my-alb/abc123",
    "dns_name": "my-alb-123.us-east-1.elb.amazonaws.com",
    "scheme": "internet-facing",
    "type": "application",
    "state": "active",
    "availability_zones": ["us-east-1a", "us-east-1b"]
  },
  "dynamic": {
    "cloudtrail_events": [
      {"event_name": "ModifyListener", "event_time": "2026-04-01T10:00:00Z", "user_identity_arn": "arn:aws:iam::123456789012:role/admin"}
    ]
  },
  "tags": { "owner": "platform-team" }
}
```

## Implemented policy packages

| Package | Purpose | Metric ID | Controls |
| --- | --- | --- | --- |
| `compliance_framework.elbv2_multi_az_redundancy` | Flags load balancers deployed across fewer than the required number of availability zones. | `ELB_TARGET_HEALTH` | `ctrl-a1-1-009`, `ctrl-a1-2-006`, `ctrl-a1-2-007` |
| `compliance_framework.elbv2_ownership_tags` | Flags load balancers missing a non-empty owner tag. | `ELBV2_OWNERSHIP_TAGS` | `ctrl-cc6-7-017` |
| `compliance_framework.elbv2_edge_endpoint_inventory` | Flags internet-facing load balancers without DNS inventory evidence or ownership. | `EDGE_ENDPOINT_INVENTORY` | `ctrl-cc5-2-005` |
| `compliance_framework.elbv2_asset_disposal` | Optionally verifies failed or inactive load balancers have deletion audit evidence. | `ELBV2_ASSET_DISPOSAL` | `ctrl-cc6-5-001`, `ctrl-cc6-7-003`, `ctrl-cc6-7-006` |
| `compliance_framework.elbv2_management_change_audit_events` | Optionally verifies listener/rule management changes are present, attributable, and timely. | `ELBV2_MANAGEMENT_CHANGE_AUDIT_EVENTS` | `ctrl-cc6-2-015`, `ctrl-cc6-2-019`, `ctrl-cc6-3-013`, `ctrl-cc6-7-018` |

All policies skip non-`loadbalancer` records. `elbv2_edge_endpoint_inventory` also skips `internal` load balancers because the control applies only to externally reachable endpoints.

## Policy data

Configurable policy defaults are stored in `policies/data.json` as flattened top-level data values. The agent may override them via its `policy_data` block.

| Name | Default | Meaning |
| --- | --- | --- |
| `data.minimum_availability_zones` | `2` | Minimum number of availability zones required for a load balancer. |
| `data.required_owner_tag_keys` | `["owner", "team"]` | Tag keys accepted as ownership evidence when present with a non-empty value. |
| `data.require_disposal_audit_events` | `false` | When `true`, inactive or failed load balancers must have a matching disposal CloudTrail event. |
| `data.disposal_delete_event_names` | `["DeleteLoadBalancer"]` | CloudTrail event names accepted as load balancer disposal evidence. |
| `data.require_management_audit_events` | `false` | When `true`, listener/rule management change events must exist, be attributable, and be recent. |
| `data.change_review_window_days` | `90` | Maximum age, in days, for the newest management change event when management audit enforcement is enabled. |
| `data.unknown_endpoint_scheme_action` | `"violation"` | How edge endpoint inventory handles load balancers whose scheme is not `internet-facing` or `internal`; set to `skip` to emit a skip reason instead. |

## Testing

```shell
opa fmt --list --fail policies
opa check --strict policies
opa test policies
```

## Bundling

```shell
make build
```
