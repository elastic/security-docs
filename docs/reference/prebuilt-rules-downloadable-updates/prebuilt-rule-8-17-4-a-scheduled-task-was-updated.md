---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-a-scheduled-task-was-updated.html
---

# A scheduled task was updated [prebuilt-rule-8-17-4-a-scheduled-task-was-updated]

Indicates the update of a scheduled task using Windows event logs. Adversaries can use these to establish persistence, by changing the configuration of a legit scheduled task. Some changes such as disabling or enabling a scheduled task are common and may may generate noise.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: System
* Resources: Investigation Guide

**Version**: 110

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4928]

**Triage and analysis**

[TBC: QUOTE]
**Investigating A scheduled task was updated**

Scheduled tasks in Windows automate routine tasks, enhancing efficiency. However, adversaries exploit this by modifying tasks to maintain persistence, often altering legitimate tasks to evade detection. The detection rule identifies suspicious updates by filtering out benign changes, such as those by system accounts or known safe tasks, focusing on anomalies that suggest malicious intent.

**Possible investigation steps**

* Review the event logs to identify the specific scheduled task that was updated, focusing on the winlog.event_data.TaskName field to determine if it matches any known malicious patterns.
* Investigate the user account associated with the update by examining the user.name field to ensure it is not a compromised account or an unauthorized user.
* Check the winlog.event_data.SubjectUserSid field to verify if the update was made by a system account or a potentially malicious user, as system accounts like S-1-5-18, S-1-5-19, and S-1-5-20 are typically benign.
* Analyze the history of changes to the scheduled task to identify any unusual or unauthorized modifications that could indicate persistence mechanisms.
* Correlate the scheduled task update with other security events or alerts to determine if it is part of a broader attack pattern or campaign.

**False positive analysis**

* Scheduled tasks updated by system accounts can be false positives. Exclude updates made by system accounts by filtering out user names ending with a dollar sign.
* Legitimate Microsoft tasks often update automatically. Exclude tasks with names containing "Microsoft" to reduce noise from these updates.
* Commonly updated tasks like User Feed Synchronization and OneDrive Reporting are typically benign. Exclude these specific task names to avoid unnecessary alerts.
* Tasks updated by well-known service SIDs such as S-1-5-18, S-1-5-19, and S-1-5-20 are generally safe. Exclude these SIDs to prevent false positives from routine system operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Review the specific scheduled task that was updated to determine if it was altered by an unauthorized user or process. Revert any unauthorized changes to their original state.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious software that may have been introduced.
* Analyze the user account that made the changes to the scheduled task. If the account is compromised, reset the password and review recent activities for further signs of compromise.
* Implement additional monitoring on the affected system and similar systems to detect any further unauthorized scheduled task updates or related suspicious activities.
* Escalate the incident to the security operations team for further investigation and to determine if the threat is part of a larger attack campaign.
* Review and update access controls and permissions related to scheduled tasks to ensure only authorized personnel can make changes, reducing the risk of future unauthorized modifications.


## Rule query [_rule_query_5883]

```js
iam where event.action == "scheduled-task-updated" and

 /* excluding tasks created by the computer account */
 not user.name : "*$" and
 not winlog.event_data.TaskName : "*Microsoft*" and
 not winlog.event_data.TaskName :
          ("\\User_Feed_Synchronization-*",
           "\\OneDrive Reporting Task-S-1-5-21*",
           "\\OneDrive Reporting Task-S-1-12-1-*",
           "\\Hewlett-Packard\\HP Web Products Detection",
           "\\Hewlett-Packard\\HPDeviceCheck",
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistant",
           "\\IpamDnsProvisioning",
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantAllUsersRun",
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantCalendarRun",
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantWakeupRun",
           "\\Microsoft\\Windows\\.NET Framework\\.NET Framework NGEN v*",
           "\\Microsoft\\VisualStudio\\Updates\\BackgroundDownload") and
  not winlog.event_data.SubjectUserSid :  ("S-1-5-18", "S-1-5-19", "S-1-5-20")
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



