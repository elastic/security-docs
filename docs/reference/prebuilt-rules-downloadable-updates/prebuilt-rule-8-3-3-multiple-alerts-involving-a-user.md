---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-multiple-alerts-involving-a-user.html
---

# Multiple Alerts Involving a User [prebuilt-rule-8-3-3-multiple-alerts-involving-a-user]

This rule uses alert data to determine when multiple different alerts involving the same user are triggered. Analysts can use this to prioritize triage and response, as these users are more likely to be compromised.

**Rule type**: threshold

**Rule indices**:

* .alerts-security.*

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

## Rule query [_rule_query_3265]

```js
signal.rule.name:* and user.name:* and not user.id:("S-1-5-18" or "S-1-5-19" or "S-1-5-20")
```


