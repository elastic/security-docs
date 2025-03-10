---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-wsus-abuse-for-lateral-movement.html
---

# Potential WSUS Abuse for Lateral Movement [potential-wsus-abuse-for-lateral-movement]

Identifies a potential Windows Server Update Services (WSUS) abuse to execute psexec to enable for lateral movement. WSUS is limited to executing Microsoft signed binaries, which limits the executables that can be used to tools published by Microsoft.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*
* logs-system.security-*
* winlogbeat-*
* logs-crowdstrike.fdr*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/wsus-spoofing](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/wsus-spoofing)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Data Source: System
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_787]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential WSUS Abuse for Lateral Movement**

Windows Server Update Services (WSUS) is a system that manages updates for Microsoft products, ensuring that only signed binaries are executed. Adversaries may exploit WSUS to run Microsoft-signed tools like PsExec for lateral movement within a network. The detection rule identifies suspicious processes initiated by WSUS, specifically targeting PsExec executions, to flag potential abuse attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of the suspicious process execution, specifically checking for the parent process name "wuauclt.exe" and the child process name "psexec64.exe" or original file name "psexec.c".
* Examine the process execution path to verify if it matches the specified directories: "?:\Windows\SoftwareDistribution\Download\Install*" or "\Device\HarddiskVolume?\Windows\SoftwareDistribution\Download\Install\*".
* Investigate the source and destination hosts involved in the alert to determine if there are any unauthorized or unexpected connections, focusing on potential lateral movement activities.
* Check the timeline of events leading up to and following the alert to identify any other suspicious activities or patterns that may indicate a broader attack.
* Correlate the alert with other security logs and alerts from data sources like Elastic Endgame, Sysmon, or Microsoft Defender for Endpoint to gather additional context and confirm the legitimacy of the activity.
* Assess the user accounts involved in the process execution to ensure they are legitimate and have not been compromised, paying attention to any anomalies in user behavior or access patterns.

**False positive analysis**

* Legitimate administrative tasks using PsExec may trigger the rule. To manage this, create exceptions for known administrative accounts or specific times when these tasks are scheduled.
* Automated scripts or software deployment tools that use PsExec for legitimate purposes can cause false positives. Identify these tools and exclude their process hashes or specific execution paths from the rule.
* Security software or monitoring tools that utilize PsExec for scanning or remediation might be flagged. Verify these tools and whitelist their activities by excluding their specific process names or parent processes.
* Test environments where PsExec is used for development or testing purposes can generate alerts. Exclude these environments by specifying their IP ranges or hostnames in the rule exceptions.

**Response and remediation**

* Isolate the affected system immediately to prevent further lateral movement within the network. Disconnect it from the network or use network segmentation to contain the threat.
* Terminate any suspicious processes identified as PsExec executions initiated by WSUS, specifically those matching the query criteria, to stop any ongoing malicious activity.
* Conduct a thorough review of the affected system’s update logs and WSUS configuration to identify any unauthorized changes or updates that may have been exploited.
* Remove any unauthorized or malicious binaries found in the specified directories (e.g., Windows\SoftwareDistribution\Download\Install) to prevent further execution.
* Reset credentials for any accounts that may have been compromised or used in the lateral movement attempt, especially those with administrative privileges.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been affected.
* Implement enhanced monitoring and logging for WSUS activities and PsExec executions to detect and respond to similar threats more effectively in the future.


## Rule query [_rule_query_835]

```js
process where host.os.type == "windows" and event.type == "start" and process.parent.name : "wuauclt.exe" and
process.executable : (
    "?:\\Windows\\SoftwareDistribution\\Download\\Install\\*",
    "\\Device\\HarddiskVolume?\\Windows\\SoftwareDistribution\\Download\\Install\\*"
) and
(process.name : "psexec64.exe" or ?process.pe.original_file_name : "psexec.c")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Exploitation of Remote Services
    * ID: T1210
    * Reference URL: [https://attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/)



