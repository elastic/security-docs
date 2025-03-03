---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-windows-subsystem-for-linux-enabled-via-dism-utility.html
---

# Windows Subsystem for Linux Enabled via Dism Utility [prebuilt-rule-8-5-1-windows-subsystem-for-linux-enabled-via-dism-utility]

Detects attempts to enable the Windows Subsystem for Linux using Microsoft Dism utility. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/](https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4415]

```js
process where event.type : "start" and
 (process.name : "Dism.exe" or process.pe.original_file_name == "DISM.EXE") and
 process.command_line : "*Microsoft-Windows-Subsystem-Linux*"
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



