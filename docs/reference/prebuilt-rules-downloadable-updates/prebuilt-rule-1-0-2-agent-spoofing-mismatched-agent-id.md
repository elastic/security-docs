---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-agent-spoofing-mismatched-agent-id.html
---

# Agent Spoofing - Mismatched Agent ID [prebuilt-rule-1-0-2-agent-spoofing-mismatched-agent-id]

Detects events that have a mismatch on the expected event agent ID. The status "agent_id_mismatch" occurs when the expected agent ID associated with the API key does not match the actual agent ID in an event. This could indicate attempts to spoof events in order to masquerade actual activity to evade detection.

**Rule type**: query

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1609]

```js
event.agent_id_status:agent_id_mismatch
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



