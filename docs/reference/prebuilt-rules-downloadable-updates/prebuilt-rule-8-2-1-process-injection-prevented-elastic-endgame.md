---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-process-injection-prevented-elastic-endgame.html
---

# Process Injection - Prevented - Elastic Endgame [prebuilt-rule-8-2-1-process-injection-prevented-elastic-endgame]

Elastic Endgame prevented Process Injection. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

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
* Privilege Escalation

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2579]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



