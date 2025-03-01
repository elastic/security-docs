---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-ransomware-detected-elastic-endgame.html
---

# Ransomware - Detected - Elastic Endgame [prebuilt-rule-0-14-3-ransomware-detected-elastic-endgame]

Elastic Endgame detected ransomware. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: critical

**Risk score**: 99

**Runs every**: 10m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Elastic Endgame

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1526]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```


