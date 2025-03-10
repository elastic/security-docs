---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-telemetrycontroller-scheduled-task-hijack.html
---

# Persistence via TelemetryController Scheduled Task Hijack [persistence-via-telemetrycontroller-scheduled-task-hijack]

Detects the successful hijack of Microsoft Compatibility Appraiser scheduled task to establish persistence with an integrity level of system.

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

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence](https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
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

## Investigation guide [_investigation_guide_628]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via TelemetryController Scheduled Task Hijack**

The Microsoft Compatibility Appraiser, part of Windows telemetry, uses scheduled tasks to assess system compatibility. Adversaries exploit this by hijacking the task to execute malicious code with system-level privileges, ensuring persistence. The detection rule identifies anomalies by monitoring processes initiated by the Appraiser that deviate from expected behavior, flagging potential hijacks for further investigation.

**Possible investigation steps**

* Review the process tree to identify the parent process CompatTelRunner.exe and verify if it has spawned any unexpected child processes that match the alert criteria.
* Examine the command-line arguments of the suspicious process to determine if they include the "-cv*" flag, which may indicate a hijack attempt.
* Check the execution history of the flagged process to see if it aligns with legitimate system activities or if it appears anomalous.
* Investigate the user account context under which the suspicious process is running to assess if it has elevated privileges or is associated with unusual user behavior.
* Correlate the alert with other security logs and telemetry data from sources like Microsoft Defender for Endpoint or Sysmon to identify any related malicious activities or indicators of compromise.
* Analyze any network connections initiated by the suspicious process to detect potential data exfiltration or communication with known malicious IP addresses.
* Review recent changes to scheduled tasks on the system to identify unauthorized modifications that could indicate persistence mechanisms.

**False positive analysis**

* Legitimate system maintenance tasks may trigger the rule if they involve processes that are not typically associated with the Microsoft Compatibility Appraiser. Users can create exceptions for known maintenance scripts or tools that are verified as safe.
* Software updates or installations that temporarily use unusual processes under the Appraiser’s context might be flagged. Users should monitor and whitelist these processes if they are part of a trusted update or installation routine.
* Custom scripts or administrative tools that leverage the Appraiser’s context for legitimate purposes could be misidentified. Users should document and exclude these scripts from detection if they are part of regular administrative operations.
* Security tools or monitoring software that interact with the Appraiser process for analysis or logging purposes may cause false positives. Users should ensure these tools are recognized and excluded from the detection rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified by the detection rule that are not part of the expected process list, such as those not matching "conhost.exe", "DeviceCensus.exe", "CompatTelRunner.exe", "DismHost.exe", "rundll32.exe", or "powershell.exe".
* Review and restore the integrity of the Microsoft Compatibility Appraiser scheduled task by resetting it to its default configuration to ensure it is not executing unauthorized code.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious files or software.
* Analyze the system for any unauthorized changes to user accounts or privileges, and revert any modifications to ensure that only legitimate users have access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the affected system and similar scheduled tasks across the network to detect any future attempts at hijacking or unauthorized modifications.


## Rule query [_rule_query_670]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "CompatTelRunner.exe" and process.args : "-cv*" and
  not process.name : ("conhost.exe",
                      "DeviceCensus.exe",
                      "CompatTelRunner.exe",
                      "DismHost.exe",
                      "rundll32.exe",
                      "powershell.exe")
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

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)



