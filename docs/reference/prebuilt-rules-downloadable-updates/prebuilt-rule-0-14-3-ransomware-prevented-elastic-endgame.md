---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-ransomware-prevented-elastic-endgame.html
---

# Ransomware - Prevented - Elastic Endgame [prebuilt-rule-0-14-3-ransomware-prevented-elastic-endgame]

Elastic Endgame prevented ransomware. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: high

**Risk score**: 73

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

## Rule query [_rule_query_1527]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```


