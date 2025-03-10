---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-temporarily-scheduled-task-creation.html
---

# Temporarily Scheduled Task Creation [prebuilt-rule-8-17-4-temporarily-scheduled-task-creation]

Indicates the creation and deletion of a scheduled task within a short time interval. Adversaries can use these to proxy malicious execution via the schedule service and perform clean up.

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
* Tactic: Execution
* Data Source: System
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4941]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Temporarily Scheduled Task Creation**

Scheduled tasks in Windows environments automate routine tasks, but adversaries exploit them for persistence and execution by creating and quickly deleting tasks to mask malicious activity. The detection rule identifies such behavior by tracking task creation and deletion within a short timeframe, flagging potential misuse when these actions occur in rapid succession without typical user patterns.

**Possible investigation steps**

* Review the winlog.computer_name field to identify the affected system and determine if it is a critical asset or part of a sensitive network segment.
* Examine the winlog.event_data.TaskName to understand the nature of the task created and deleted, and assess if it aligns with known legitimate tasks or appears suspicious.
* Investigate the user.name associated with the task creation and deletion events to determine if the activity was performed by a legitimate user or potentially compromised account.
* Check for any related events or logs around the same timeframe on the affected system to identify any additional suspicious activities or anomalies.
* Correlate the task creation and deletion events with other security alerts or incidents to determine if this activity is part of a broader attack campaign or isolated incident.

**False positive analysis**

* Routine administrative tasks may trigger the rule if system administrators frequently create and delete scheduled tasks for maintenance purposes. To manage this, create exceptions for known administrative accounts or specific task names that are part of regular operations.
* Automated scripts or software updates that temporarily create scheduled tasks can also cause false positives. Identify these scripts or update processes and exclude their associated user accounts or task names from the detection rule.
* Some legitimate applications may use scheduled tasks for temporary operations. Review application documentation to confirm such behavior and exclude these applications by their task names or associated user accounts.
* In environments with frequent testing or development activities, developers might create and delete tasks as part of their workflow. Consider excluding developer accounts or specific task names used in testing environments to reduce noise.
* Scheduled tasks created by monitoring or security tools for short-lived operations can be mistaken for malicious activity. Verify these tools' behavior and exclude their task names or user accounts if they are known to be safe.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Review the scheduled task details, including the task name and associated scripts or executables, to identify any malicious payloads or commands.
* Terminate any malicious processes or executables identified from the scheduled task analysis to stop ongoing threats.
* Restore any altered or deleted system files from a known good backup to ensure system integrity.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems are affected.
* Implement additional monitoring and alerting for similar scheduled task activities to enhance detection and prevent recurrence of this threat.


## Rule query [_rule_query_5896]

```js
sequence by winlog.computer_name, winlog.event_data.TaskName with maxspan=5m
   [iam where event.action == "scheduled-task-created" and not user.name : "*$"]
   [iam where event.action == "scheduled-task-deleted" and not user.name : "*$"]
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



