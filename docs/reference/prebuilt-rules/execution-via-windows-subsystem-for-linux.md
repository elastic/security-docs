---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-via-windows-subsystem-for-linux.html
---

# Execution via Windows Subsystem for Linux [execution-via-windows-subsystem-for-linux]

Detects attempts to execute a program on the host from the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://learn.microsoft.com/en-us/windows/wsl/wsl-config](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_319]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution via Windows Subsystem for Linux**

Windows Subsystem for Linux (WSL) allows users to run Linux binaries natively on Windows, providing a seamless integration of Linux tools. Adversaries may exploit WSL to execute malicious scripts or binaries, bypassing traditional Windows security mechanisms. The detection rule identifies suspicious executions initiated by WSL processes, excluding known safe executables, to flag potential misuse for defense evasion.

**Possible investigation steps**

* Review the process details to identify the executable path and determine if it matches any known malicious or suspicious binaries not listed in the safe executables.
* Investigate the parent process, specifically wsl.exe or wslhost.exe, to understand how the execution was initiated and if it aligns with expected user behavior or scheduled tasks.
* Check the user account associated with the process execution to verify if the activity is consistent with the user’s typical behavior or if the account may have been compromised.
* Analyze the event dataset, especially if it is from crowdstrike.fdr, to gather additional context about the process execution and any related activities on the host.
* Correlate the alert with other security events or logs from data sources like Microsoft Defender for Endpoint or SentinelOne to identify any related suspicious activities or patterns.
* Assess the risk score and severity in the context of the organization’s environment to prioritize the investigation and response actions accordingly.

**False positive analysis**

* Legitimate administrative tasks using WSL may trigger alerts. Users can create exceptions for known administrative scripts or binaries that are frequently executed via WSL.
* Development environments often use WSL for compiling or testing code. Exclude specific development tools or scripts that are regularly used by developers to prevent unnecessary alerts.
* Automated system maintenance scripts running through WSL can be mistaken for malicious activity. Identify and whitelist these scripts to reduce false positives.
* Security tools or monitoring solutions that leverage WSL for legitimate purposes should be identified and excluded from detection to avoid interference with their operations.
* Frequent use of WSL by specific users or groups for non-malicious purposes can be managed by creating user-based exceptions, allowing their activities to proceed without triggering alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified as being executed via WSL that are not part of the known safe executables list.
* Conduct a thorough review of the affected system’s WSL configuration and installed Linux distributions to identify unauthorized changes or installations.
* Remove any unauthorized or malicious scripts and binaries found within the WSL environment.
* Restore the system from a known good backup if malicious activity has compromised system integrity.
* Update and patch the system to ensure all software, including WSL, is up to date to mitigate known vulnerabilities.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_337]

```js
process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : ("wsl.exe", "wslhost.exe") and
  not process.executable : (
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "?:\\Windows\\System32\\conhost.exe",
        "?:\\Windows\\System32\\lxss\\wslhost.exe",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\Sys?????\\wslconfig.exe"
  ) and
  not (
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume?\\Program Files (x86)\\*",
        "\\Device\\HarddiskVolume?\\Program Files\\*",
        "\\Device\\HarddiskVolume?\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\conhost.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\lxss\\wslhost.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\WerFault.exe",
        "\\Device\\HarddiskVolume?\\Windows\\Sys?????\\wslconfig.exe"
      )
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



