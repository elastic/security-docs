---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-build-engine-started-by-a-system-process.html
---

# Microsoft Build Engine Started by a System Process [microsoft-build-engine-started-by-a-system-process]

An instance of MSBuild, the Microsoft Build Engine, was started by Explorer or the WMI (Windows Management Instrumentation) subsystem. This behavior is unusual and is sometimes used by malicious payloads.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_527]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Build Engine Started by a System Process**

The Microsoft Build Engine (MSBuild) is a platform for building applications, typically invoked by developers. However, adversaries exploit it to execute malicious code, leveraging its trusted status to bypass security measures. The detection rule identifies unusual MSBuild activity initiated by system processes like Explorer or WMI, which may indicate an attempt to evade defenses and execute unauthorized actions.

**Possible investigation steps**

* Review the process tree to understand the parent-child relationship, focusing on instances where MSBuild.exe is started by explorer.exe or wmiprvse.exe.
* Check the command line arguments used to start MSBuild.exe for any suspicious or unusual parameters that could indicate malicious activity.
* Investigate the user account associated with the process to determine if it aligns with expected behavior or if it might be compromised.
* Examine recent file modifications or creations in directories commonly used by MSBuild to identify any unauthorized or unexpected files.
* Correlate the event with other security alerts or logs from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context on the activity.
* Assess the network activity of the host during the time of the alert to identify any potential data exfiltration or communication with known malicious IP addresses.

**False positive analysis**

* Legitimate software installations or updates may trigger MSBuild.exe to start from Explorer or WMI. Monitor these events and verify if they coincide with known software changes.
* Development environments where MSBuild is frequently used might see this behavior as part of normal operations. Identify and document these environments to create exceptions for known development machines.
* Automated scripts or administrative tools that leverage MSBuild for legitimate tasks can cause false positives. Review and whitelist these scripts or tools if they are verified as non-malicious.
* System maintenance tasks initiated by IT personnel might use MSBuild in a manner that appears suspicious. Coordinate with IT to understand routine maintenance activities and exclude them from alerts.
* Security software or monitoring tools that interact with MSBuild for scanning or analysis purposes should be identified and excluded from triggering alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the MSBuild.exe process if it is confirmed to be executing unauthorized or malicious code.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious payloads or associated files.
* Review and analyze the parent processes (explorer.exe or wmiprvse.exe) to determine if they have been compromised or are executing other suspicious activities.
* Restore the system from a known good backup if any critical system files or applications have been altered or corrupted.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for MSBuild.exe and related processes to detect similar activities in the future, ensuring alerts are configured for rapid response.


## Rule query [_rule_query_566]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



