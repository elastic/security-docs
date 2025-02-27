---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-endpoint-security.html
---

# Endpoint Security [prebuilt-rule-8-3-3-endpoint-security]

Generates a detection alert each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to immediately begin investigating your Endpoint alerts.

**Rule type**: query

**Rule indices**:

* logs-endpoint.alerts-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Elastic
* Endpoint Security

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3331]

```js
event.kind:alert and event.module:(endpoint and not endgame)
```


