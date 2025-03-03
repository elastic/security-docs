---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-host-files-system-changes-via-windows-subsystem-for-linux.html
---

# Host Files System Changes via Windows Subsystem for Linux [prebuilt-rule-8-17-4-host-files-system-changes-via-windows-subsystem-for-linux]

Detects files creation and modification on the host system from the the Windows Subsystem for Linux. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/microsoft/WSL](https://github.com/microsoft/WSL)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4822]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Host Files System Changes via Windows Subsystem for Linux**

Windows Subsystem for Linux (WSL) allows users to run a Linux environment directly on Windows, facilitating seamless file access between systems. Adversaries may exploit WSL to modify host files stealthily, bypassing traditional security measures. The detection rule identifies suspicious file operations initiated by WSL processes, particularly those involving the Plan9FileSystem, to flag potential defense evasion attempts.

**Possible investigation steps**

* Review the process details for the "dllhost.exe" instance that triggered the alert, focusing on the command line arguments to confirm the presence of the Plan9FileSystem CLSID `"{DFB65C4C-B34F-435D-AFE9-A86218684AA8}"`.
* Examine the file paths involved in the alert to determine if any sensitive or critical files were accessed or modified outside of typical user directories, excluding the Downloads folder.
* Investigate the parent process of "dllhost.exe" to understand the context of its execution and identify any potentially malicious parent processes.
* Check the timeline of events leading up to and following the alert to identify any other suspicious activities or related alerts that may indicate a broader attack pattern.
* Correlate the alert with user activity logs to determine if the actions were performed by a legitimate user or if there are signs of compromised credentials or unauthorized access.

**False positive analysis**

* Routine file operations by legitimate applications using WSL may trigger alerts. Identify and whitelist these applications to prevent unnecessary alerts.
* Development activities involving WSL, such as compiling code or running scripts, can generate false positives. Exclude specific development directories or processes from monitoring.
* Automated backup or synchronization tools that interact with WSL might be flagged. Configure exceptions for these tools by specifying their process names or file paths.
* System maintenance tasks that involve WSL, like updates or system checks, could be mistaken for suspicious activity. Schedule these tasks during known maintenance windows and adjust monitoring rules accordingly.
* Frequent downloads or file transfers to directories outside the typical user download paths may appear suspicious. Define clear policies for acceptable file paths and exclude them from alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes associated with "dllhost.exe" that are linked to the Plan9FileSystem CLSID to stop ongoing malicious activities.
* Conduct a thorough review of recent file changes on the host system to identify and restore any unauthorized modifications or deletions.
* Revoke any unauthorized access or permissions granted to WSL that may have been exploited by the adversary.
* Update and patch the Windows Subsystem for Linux and related components to mitigate any known vulnerabilities that could be exploited.
* Monitor for any recurrence of similar activities by setting up alerts for processes and file operations involving "dllhost.exe" and the Plan9FileSystem.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_5777]

```js
sequence by process.entity_id with maxspan=5m
 [process where host.os.type == "windows" and event.type == "start" and
  process.name : "dllhost.exe" and
   /* Plan9FileSystem CLSID - WSL Host File System Worker */
  process.command_line : "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*"]
 [file where host.os.type == "windows" and process.name : "dllhost.exe" and not file.path : "?:\\Users\\*\\Downloads\\*"]
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



