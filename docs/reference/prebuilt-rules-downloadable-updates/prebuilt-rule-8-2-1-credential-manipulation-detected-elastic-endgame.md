---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-credential-manipulation-detected-elastic-endgame.html
---

# Credential Manipulation - Detected - Elastic Endgame [prebuilt-rule-8-2-1-credential-manipulation-detected-elastic-endgame]

Elastic Endgame detected Credential Manipulation. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Elastic
* Elastic Endgame
* Threat Detection
* Privilege Escalation

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2574]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



