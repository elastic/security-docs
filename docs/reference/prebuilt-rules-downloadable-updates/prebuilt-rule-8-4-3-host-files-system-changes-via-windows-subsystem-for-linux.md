---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-host-files-system-changes-via-windows-subsystem-for-linux.html
---

# Host Files System Changes via Windows Subsystem for Linux [prebuilt-rule-8-4-3-host-files-system-changes-via-windows-subsystem-for-linux]

Detects files creation and modification on the host system from the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

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

* [https://github.com/microsoft/WSL](https://github.com/microsoft/WSL)

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

## Rule query [_rule_query_4291]

```js
sequence by process.entity_id with maxspan=5m
 [process where event.type == "start" and
  process.name : "dllhost.exe" and
   /* Plan9FileSystem CLSID - WSL Host File System Worker */
  process.command_line : "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*"]
 [file where process.name : "dllhost.exe" and not file.path : "?:\\Users\\*\\Downloads\\*"]
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



