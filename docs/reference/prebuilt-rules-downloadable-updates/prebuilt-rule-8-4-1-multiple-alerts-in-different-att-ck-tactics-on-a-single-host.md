---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-multiple-alerts-in-different-att-ck-tactics-on-a-single-host.html
---

# Multiple Alerts in Different ATT&CK Tactics on a Single Host [prebuilt-rule-8-4-1-multiple-alerts-in-different-att-ck-tactics-on-a-single-host]

This rule uses alert data to determine when multiple alerts in different phases of an attack involving the same host are triggered. Analysts can use this to prioritize triage and response, as these hosts are more likely to be compromised.

**Rule type**: threshold

**Rule indices**:

* .alerts-*

**Severity**: high

**Risk score**: 73

**Runs every**: 1h

**Searches indices from**: now-24h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Threat Detection
* Higher-Order Rules

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2952]

```js
signal.rule.name:* and kibana.alert.rule.threat.tactic.id:*
```


