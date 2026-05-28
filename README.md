# AWS ELBv2 target group policies

Standalone OPA/Rego policy bundle for target group evidence emitted by the `aws-elbv2` Compliance Framework plugin.

## Input schema

Each policy evaluates documents where `input.resource.type == "target-group"`.

```json
{
  "schema_version": "v1",
  "source": "aws-elbv2",
  "account": { "account_id": "123456789012" },
  "region": { "name": "us-east-1" },
  "resource": {
    "id": "targetgroup/my-tg/abc123",
    "arn": "arn:aws:elasticloadbalancing:...:targetgroup/my-tg/abc123",
    "type": "target-group"
  },
  "config": {
    "target_group_arn": "arn:aws:elasticloadbalancing:...:targetgroup/my-tg/abc123",
    "load_balancer_arn": "arn:aws:elasticloadbalancing:...:loadbalancer/app/my-alb/abc",
    "protocol": "HTTP",
    "port": 80,
    "health_check_protocol": "HTTP",
    "health_check_path": "/healthz",
    "healthy_threshold_count": 3,
    "unhealthy_threshold_count": 3
  }
}
```

All policies skip non-`target-group` records.

## Implemented policy packages

| Package | Purpose | Metric ID | Controls |
| --- | --- | --- | --- |
| `compliance_framework.elbv2_health_check_configured` | Flags target groups with missing health-check protocol, missing required HTTP/HTTPS path, or threshold counts outside policy bounds. | `ELB_TARGET_HEALTH` | `ctrl-a1-1-009`, `ctrl-a1-2-007` |
| `compliance_framework.elbv2_target_movement_restrictions` | Optionally restricts target group backend protocols and ports to approved lists. | `N/A` | `ctrl-cc6-7-002`, `ctrl-cc6-7-005` |

AWS always assigns some health-check defaults, so the natural failure cases are threshold bounds or the required-path rule, not disabled health checks.

## Policy data

Configurable policy defaults are stored in `policies/data.json` as flattened top-level `data.*` values. The agent may override them via its `policy_data` block.

| Name | Default | Meaning |
| --- | --- | --- |
| `data.min_healthy_threshold` | `2` | Minimum allowed `healthy_threshold_count` for target group health checks. |
| `data.max_unhealthy_threshold` | `10` | Maximum allowed `unhealthy_threshold_count` for target group health checks. |
| `data.require_health_check_path_for_http` | `true` | When `true`, HTTP and HTTPS health checks must include a non-empty `health_check_path`. |
| `data.approved_target_protocols` | `[]` | Optional allow list of target group backend protocols. Empty means protocol approval is not enforced. |
| `data.approved_target_ports` | `[]` | Optional allow list of target group backend ports. Empty means port approval is not enforced. |

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
