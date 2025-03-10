---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/indirect-command-execution-via-forfiles-pcalua.html
---

# Indirect Command Execution via Forfiles/Pcalua [indirect-command-execution-via-forfiles-pcalua]

Identifies indirect command execution via Program Compatibility Assistant (pcalua.exe) or forfiles.exe.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-system.security*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_463]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("pcalua.exe", "forfiles.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indirect Command Execution
    * ID: T1202
    * Reference URL: [https://attack.mitre.org/techniques/T1202/](https://attack.mitre.org/techniques/T1202/)



