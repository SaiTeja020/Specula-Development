# Permission evidence exports

Place JSON objects or arrays under `access/` in the existing evidence ZIP, for example
`access/permissions.json`. These are source declarations, preserved and normalized as
OCSF GenericEvent records. A modeled grant does not establish actual access or exploitation.
Each object requires `schema_version`, `provider`, `timestamp` with UTC offset,
`scope_id`, `snapshot_id`, optional `host`, and `payload` (maximum 256 KiB).

## Windows token and ordered DACL

```json
{
  "schema_version": "specula.access.v1",
  "provider": "windows_dacl",
  "timestamp": "2026-10-15T00:00:00Z",
  "scope_id": "EXAMPLE-DOMAIN",
  "snapshot_id": "export-001",
  "host": "HOST-1",
  "payload": {
    "subject": {
      "sid": "S-1-5-21-10",
      "token_complete": true,
      "groups": [{"sid": "S-1-1-0", "enabled": true}]
    },
    "resource": {
      "id": "volume-1/target",
      "dacl_complete": true,
      "dacl": [{"kind": "allow", "sid": "S-1-1-0", "mask": 1}]
    },
    "request": {"mask": 1},
    "group_memberships": []
  }
}
```

Preserve actual ACE order. `dacl: null` explicitly declares a null DACL; an empty
array declares an empty DACL. A missing field is unknown. Groups require actual
enabled/disabled attributes; use `deny_only: true` for deny-only SIDs. Optional ACE
fields are `inherit_only`, `inherited`, `object_type` (rights GUID) and `condition`.
Object-specific checks require the matching request GUID. Conditional/unsupported
ACEs and unmapped generic/MAXIMUM_ALLOWED rights remain indeterminate/unavailable.
Directory membership edges use `member_sid` and `group_sid`; they are not silently
added to a token. Owner/privilege overrides, mandatory integrity, restricted/claims
tokens and central authorization are outside this DACL-only model.

## AWS IAM source policy model

```json
{
  "schema_version": "specula.access.v1",
  "provider": "aws_iam",
  "timestamp": "2026-10-15T00:00:00Z",
  "scope_id": "123456789012",
  "snapshot_id": "iam-export-001",
  "payload": {
    "principal_arn": "arn:aws:iam::123456789012:user/alice",
    "request": {
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::case-bucket/log.json"
    },
    "context": {},
    "same_account": true,
    "applicable_layers_complete": true,
    "resource_policies_absent": true,
    "service_controls_complete": true,
    "policy_layers": [{
      "kind": "identity",
      "complete": true,
      "policies": [{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::case-bucket/*"}]
      }]
    }]
  }
}
```

Include every applicable `identity`, `boundary`, `session`, `scp` and `rcp` layer,
with policies applying at the same scope. An identity layer is mandatory. Only
declare completeness/absence when supported by the collected policy inventory.
Explicit denies override grants; required layers intersect. Supported conditions:
StringEquals, StringLike, ArnEquals, ArnLike, Bool and Null. Condition values and
context values use strings. Unknown operators, missing context, policy variables,
resource/trust policies, cross-account/root/session principals and service-specific
authorization cannot silently become grants. This tool does not call AWS APIs.

References: [Windows DACL access checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[IAM evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).
