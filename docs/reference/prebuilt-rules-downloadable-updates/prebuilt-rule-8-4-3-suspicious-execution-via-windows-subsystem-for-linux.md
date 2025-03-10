---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-suspicious-execution-via-windows-subsystem-for-linux.html
---

# Suspicious Execution via Windows Subsystem for Linux [prebuilt-rule-8-4-3-suspicious-execution-via-windows-subsystem-for-linux]

Detects Linux Bash commands from the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

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
* [https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/)
* [https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1](https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution
* Defense Evasion
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4288]

```js
process where event.type : "start" and
 (
  ((process.executable : "?:\\Windows\\System32\\bash.exe" or process.pe.original_file_name == "Bash.exe") and
  not process.command_line : ("bash", "bash.exe")) or
  process.executable : "?:\\Users\\*\\AppData\\Local\\Packages\\*\\rootfs\\usr\\bin\\bash" or
  (process.parent.name : "wsl.exe" and process.parent.command_line : "bash*" and not process.name : "wslhost.exe") or
  (process.name : "wsl.exe" and process.args : ("curl", "/etc/shadow", "/etc/passwd", "cat","--system", "root", "-e", "--exec", "bash", "/mnt/c/*"))
  ) and
  not process.parent.executable : ("?:\\Program Files\\Docker\\*.exe", "?:\\Program Files (x86)\\Docker\\*.exe")
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



