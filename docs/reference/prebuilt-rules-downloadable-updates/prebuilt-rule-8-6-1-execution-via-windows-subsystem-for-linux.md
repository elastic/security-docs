---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-execution-via-windows-subsystem-for-linux.html
---

# Execution via Windows Subsystem for Linux [prebuilt-rule-8-6-1-execution-via-windows-subsystem-for-linux]

Detects attempts to execute a program on the host from the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

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

* [https://learn.microsoft.com/en-us/windows/wsl/wsl-config](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

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

## Rule query [_rule_query_4540]

```js
process where event.type : "start" and
 process.parent.executable :
    ("?:\\Windows\\System32\\wsl.exe",
     "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl.exe",
     "?:\\Windows\\System32\\wslhost.exe",
     "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wslhost.exe") and
  not process.executable :
           ("?:\\Windows\\System32\\conhost.exe",
            "?:\\Windows\\System32\\lxss\\wslhost.exe",
            "?:\\Windows\\Sys*\\wslconfig.exe",
            "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*")
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



