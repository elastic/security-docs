---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-execution-via-windows-subsystem-for-linux.html
---

# Suspicious Execution via Windows Subsystem for Linux [suspicious-execution-via-windows-subsystem-for-linux]

Detects Linux Bash commands from the the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/](https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/)
* [https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/)
* [https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1](https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_987]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Execution via Windows Subsystem for Linux**

Windows Subsystem for Linux (WSL) allows users to run Linux binaries natively on Windows, providing a seamless integration of Linux tools. Adversaries may exploit WSL to execute Linux commands stealthily, bypassing traditional Windows security measures. The detection rule identifies unusual WSL activity by monitoring specific executable paths, command-line arguments, and parent-child process relationships, flagging deviations from typical usage patterns to uncover potential threats.

**Possible investigation steps**

* Review the process command line and executable path to determine if the execution of bash.exe or any other Linux binaries is expected or authorized for the user or system in question.
* Investigate the parent-child process relationship, especially focusing on whether wsl.exe is the parent process and if it has spawned any unexpected child processes that are not wslhost.exe.
* Examine the command-line arguments used with wsl.exe for any suspicious or unauthorized commands, such as accessing sensitive files like /etc/shadow or /etc/passwd, or using network tools like curl.
* Check the user’s activity history and system logs to identify any patterns of behavior that might indicate misuse or compromise, particularly focusing on any deviations from typical usage patterns.
* Correlate the alert with other security events or logs from data sources like Elastic Endgame, Microsoft Defender for Endpoint, or Sysmon to gather additional context and determine if this is part of a broader attack or isolated incident.

**False positive analysis**

* Frequent use of WSL for legitimate development tasks may trigger alerts. Users can create exceptions for specific user accounts or directories commonly used for development to reduce noise.
* Automated scripts or tools that utilize WSL for system maintenance or monitoring might be flagged. Identify these scripts and whitelist their specific command-line patterns or parent processes.
* Docker-related processes may cause false positives due to their interaction with WSL. Exclude Docker executable paths from the detection rule to prevent unnecessary alerts.
* Visual Studio Code extensions that interact with WSL can generate alerts. Exclude known non-threatening extensions by specifying their command-line arguments in the exception list.
* Regular system updates or administrative tasks that involve WSL might be misidentified. Document these activities and adjust the detection rule to recognize them as benign.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, such as those involving bash.exe or wsl.exe with unusual command-line arguments.
* Conduct a thorough review of the affected system’s WSL configuration and installed Linux distributions to identify any unauthorized changes or installations.
* Remove any unauthorized or suspicious Linux binaries or scripts found within the WSL environment.
* Reset credentials for any accounts that may have been compromised, especially if sensitive files like /etc/shadow or /etc/passwd were accessed.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for WSL activities across the network to detect similar threats in the future, ensuring that alerts are promptly reviewed and acted upon.


## Rule query [_rule_query_1036]

```js
process where host.os.type == "windows" and event.type : "start" and
  (
    (
      (process.executable : "?:\\Windows\\System32\\bash.exe" or ?process.pe.original_file_name == "Bash.exe") and
      not process.command_line : ("bash", "bash.exe")
    ) or
    process.executable : "?:\\Users\\*\\AppData\\Local\\Packages\\*\\rootfs\\usr\\bin\\bash" or
    (
      process.parent.name : "wsl.exe" and process.parent.command_line : "bash*" and not process.name : "wslhost.exe"
    ) or
    (
      process.name : "wsl.exe" and process.args : (
        "curl", "/etc/shadow", "/etc/passwd", "cat", "--system", "root", "-e", "--exec", "bash", "/mnt/c/*"
      ) and not process.args : ("wsl-bootstrap", "docker-desktop-data", "*.vscode-server*")
    )
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



