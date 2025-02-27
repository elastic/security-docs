---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-agent-spoofing-multiple-hosts-using-same-agent.html
---

# Agent Spoofing - Multiple Hosts Using Same Agent [prebuilt-rule-1-0-2-agent-spoofing-multiple-hosts-using-same-agent]

Detects when multiple hosts are using the same agent ID. This could occur in the event of an agent being taken over and used to inject illegitimate documents into an instance as an attempt to spoof events in order to masquerade actual activity to evade detection.

**Rule type**: threshold

**Rule indices**:

* logs-*
* metrics-*
* traces-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1610]

```js
event.agent_id_status:*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



