---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/scheduled-task-created-by-a-windows-script.html
---

# Scheduled Task Created by a Windows Script [scheduled-task-created-by-a-windows-script]

A scheduled task was created by a Windows script via cscript.exe, wscript.exe or powershell.exe. This can be abused by an adversary to establish persistence.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-endpoint.events.library-*
* logs-windows.sysmon_operational-*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_903]

**Triage and analysis**

Decode the base64 encoded Tasks Actions registry value to investigate the task’s configured action.


## Rule query [_rule_query_959]

```js
sequence by host.id with maxspan = 30s
  [any where host.os.type == "windows" and
    (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
    (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and
    process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")]
  [registry where host.os.type == "windows" and event.type == "change" and registry.value : "Actions" and
    registry.path : (
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"
  )]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)



