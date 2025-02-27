---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-credential-dumping-prevented-elastic-endgame.html
---

# Credential Dumping - Prevented - Elastic Endgame [prebuilt-rule-8-2-1-credential-dumping-prevented-elastic-endgame]

Elastic Endgame prevented Credential Dumping. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Elastic
* Elastic Endgame
* Threat Detection
* Credential Access

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2571]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



