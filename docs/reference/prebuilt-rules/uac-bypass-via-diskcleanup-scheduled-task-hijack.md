---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/uac-bypass-via-diskcleanup-scheduled-task-hijack.html
---

# UAC Bypass via DiskCleanup Scheduled Task Hijack [uac-bypass-via-diskcleanup-scheduled-task-hijack]

Identifies User Account Control (UAC) bypass via hijacking DiskCleanup Scheduled Task. Attackers bypass UAC to stealthily execute code with elevated permissions.

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
* Tactic: Privilege Escalation
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

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1085]

**Triage and analysis**

[TBC: QUOTE]
**Investigating UAC Bypass via DiskCleanup Scheduled Task Hijack**

User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes. Adversaries may exploit the DiskCleanup Scheduled Task to bypass UAC, executing code with elevated privileges. The detection rule identifies suspicious processes using specific arguments and executables not matching known safe paths, flagging potential UAC bypass attempts for further investigation.

**Possible investigation steps**

* Review the process details to confirm the presence of suspicious arguments "/autoclean" and "/d" in the process execution.
* Verify the executable path of the process to ensure it does not match known safe paths such as "C:\Windows\System32\cleanmgr.exe" or "C:\Windows\SysWOW64\cleanmgr.exe".
* Investigate the parent process to determine how the suspicious process was initiated and assess if it was triggered by a legitimate application or script.
* Check the user account under which the process was executed to identify if it aligns with expected user behavior or if it indicates potential compromise.
* Analyze recent system changes or scheduled tasks to identify any unauthorized modifications that could facilitate UAC bypass.
* Correlate the event with other security alerts or logs from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context on the activity.
* Assess the risk and impact of the event by considering the severity and risk score, and determine if further containment or remediation actions are necessary.

**False positive analysis**

* Legitimate system maintenance tools or scripts may trigger the rule if they use similar arguments and executables not listed in the safe paths. Review the process origin and context to determine if it is part of routine maintenance.
* Custom administrative scripts that automate disk cleanup tasks might be flagged. Verify the script’s source and purpose, and consider adding it to an exception list if it is deemed safe.
* Software updates or installations that temporarily use disk cleanup functionalities could be misidentified. Monitor the timing and context of these events, and exclude known update processes from the rule.
* Third-party disk management tools that mimic or extend Windows disk cleanup features may cause alerts. Validate the tool’s legitimacy and add it to the exclusion list if it is a trusted application.
* Scheduled tasks created by IT departments for system optimization might match the rule’s criteria. Confirm the task’s legitimacy and adjust the rule to exclude these specific tasks if they are verified as non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule that are not using the legitimate DiskCleanup executables.
* Conduct a thorough review of scheduled tasks on the affected system to identify and remove any unauthorized or malicious tasks that may have been created or modified.
* Restore any altered system files or configurations to their original state using known good backups or system restore points.
* Update and patch the affected system to the latest security updates to mitigate any known vulnerabilities that could be exploited for UAC bypass.
* Monitor the affected system and network for any signs of recurring unauthorized activity or similar UAC bypass attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_1141]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and process.executable != null and
 not process.executable : (
        "C:\\Windows\\System32\\cleanmgr.exe",
        "C:\\Windows\\SysWOW64\\cleanmgr.exe",
        "C:\\Windows\\System32\\taskhostw.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\cleanmgr.exe",
        "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\cleanmgr.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\taskhostw.exe"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



