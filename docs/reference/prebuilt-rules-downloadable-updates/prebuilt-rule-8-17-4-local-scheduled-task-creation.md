---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-local-scheduled-task-creation.html
---

# Local Scheduled Task Creation [prebuilt-rule-8-17-4-local-scheduled-task-creation]

Indicates the creation of a scheduled task. Adversaries can use these to establish persistence, move laterally, and/or escalate privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1)
* [https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-2](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-2)
* [https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine](https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine)
* [https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper](https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4912]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Local Scheduled Task Creation**

Scheduled tasks in Windows automate routine tasks, but adversaries exploit them for persistence, lateral movement, or privilege escalation. They may use command-line tools like `schtasks.exe` to create tasks under non-system accounts. The detection rule identifies suspicious task creation by monitoring specific processes and command-line arguments, excluding those initiated by system-level users, to flag potential misuse.

**Possible investigation steps**

* Review the process entity ID to identify the parent process that initiated the scheduled task creation. This can provide context on whether the task was created by a legitimate application or a potentially malicious one.
* Examine the command-line arguments used with schtasks.exe, specifically looking for unusual or suspicious parameters that might indicate malicious intent, such as unexpected task names or execution paths.
* Check the user account associated with the task creation to determine if it is a non-system account and assess whether this account should have the capability to create scheduled tasks.
* Investigate the integrity level of the process to confirm it is not running with elevated privileges, which could indicate an attempt to bypass security controls.
* Correlate the event with other recent activities on the host, such as file modifications or network connections, to identify any patterns or additional indicators of compromise.
* Review the code signature of the initiating process to determine if it is trusted or untrusted, which can help assess the legitimacy of the process creating the task.

**False positive analysis**

* Scheduled tasks created by legitimate administrative tools or scripts may trigger false positives. Users should identify and whitelist these known benign processes to prevent unnecessary alerts.
* Routine maintenance tasks initiated by IT departments, such as software updates or system checks, can be mistaken for suspicious activity. Exclude these tasks by specifying their unique process names or command-line arguments.
* Tasks created by trusted third-party applications for legitimate purposes might be flagged. Review and exclude these applications by verifying their code signatures and adding them to an exception list.
* Automated tasks set up by non-system accounts for regular operations, like backups or monitoring, can be misinterpreted. Document these tasks and exclude them based on their specific parameters or user accounts involved.
* Consider excluding tasks with a consistent and verified schedule that aligns with organizational policies, as these are less likely to be malicious.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious scheduled tasks identified by the alert using Task Scheduler or command-line tools like schtasks.exe to stop further execution.
* Review and remove any unauthorized scheduled tasks created by non-system accounts to eliminate persistence mechanisms.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious artifacts.
* Analyze the user account involved in the task creation for signs of compromise, and reset credentials if necessary to prevent further unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for scheduled task creation events to detect similar threats in the future, ensuring alerts are configured to notify the appropriate teams promptly.


## Rule query [_rule_query_5867]

```js
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.type != "end" and
    ((process.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                      "powershell.exe", "pwsh.exe", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe", "winrshost.exe") or
    process.pe.original_file_name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                                     "powershell.exe", "pwsh.dll", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe",
                                     "winrshost.exe")) or
    ?process.code_signature.trusted == false)] by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and
    (process.name : "schtasks.exe" or process.pe.original_file_name == "schtasks.exe") and
    process.args : ("/create", "-create") and process.args : ("/RU", "/SC", "/TN", "/TR", "/F", "/XML") and
    /* exclude SYSTEM Integrity Level - look for task creations by non-SYSTEM user */
    not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System")
  ] by process.parent.entity_id
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



