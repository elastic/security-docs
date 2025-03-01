---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-attempt-to-install-kali-linux-via-wsl.html
---

# Attempt to Install Kali Linux via WSL [prebuilt-rule-8-6-1-attempt-to-install-kali-linux-via-wsl]

Detects attempts to install or use Kali Linux via Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

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

## Rule query [_rule_query_4543]

```js
process where event.type == "start" and
(
 (process.name : "wsl.exe" and process.args : ("-d", "--distribution", "-i", "--install") and process.args : "kali*") or
 process.executable :
        ("?:\\Users\\*\\AppData\\Local\\packages\\kalilinux*",
         "?:\\Users\\*\\AppDara\\Local\\Microsoft\\WindowsApps\\kali.exe",
         "?:\\Program Files*\\WindowsApps\\KaliLinux.*\\kali.exe")
 )
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



