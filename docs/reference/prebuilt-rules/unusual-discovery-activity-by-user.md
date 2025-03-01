---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-discovery-activity-by-user.html
---

# Unusual Discovery Activity by User [unusual-discovery-activity-by-user]

This rule leverages alert data from various Discovery building block rules to alert on signals with unusual unique host.id and user.id entries.

**Rule type**: new_terms

**Rule indices**:

* .alerts-security.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: Higher-Order Rule
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1164]

```js
host.os.type:windows and event.kind:signal and kibana.alert.rule.rule_id:(
  "d68e95ad-1c82-4074-a12a-125fe10ac8ba" or "7b8bfc26-81d2-435e-965c-d722ee397ef1" or
  "0635c542-1b96-4335-9b47-126582d2c19a" or "6ea55c81-e2ba-42f2-a134-bccf857ba922" or
  "e0881d20-54ac-457f-8733-fe0bc5d44c55" or "06568a02-af29-4f20-929c-f3af281e41aa" or
  "c4e9ed3e-55a2-4309-a012-bc3c78dad10a" or "51176ed2-2d90-49f2-9f3d-17196428b169" or
  "1d72d014-e2ab-4707-b056-9b96abe7b511"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)



