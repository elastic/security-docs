---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-outbound-scheduled-task-activity-via-powershell.html
---

# Outbound Scheduled Task Activity via PowerShell [prebuilt-rule-8-17-4-outbound-scheduled-task-activity-via-powershell]

Identifies the PowerShell process loading the Task Scheduler COM DLL followed by an outbound RPC network connection within a short time period. This may indicate lateral movement or remote discovery via scheduled tasks.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.library-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4854]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Outbound Scheduled Task Activity via PowerShell**

PowerShell, a powerful scripting language in Windows, can automate tasks via the Task Scheduler. Adversaries exploit this by creating scheduled tasks to execute malicious scripts, facilitating lateral movement or remote discovery. The detection rule identifies suspicious PowerShell activity by monitoring for the Task Scheduler DLL load and subsequent outbound RPC connections, signaling potential misuse.

**Possible investigation steps**

* Review the alert details to identify the specific host.id and process.entity_id associated with the suspicious activity.
* Examine the process execution history on the affected host to determine if the PowerShell process (powershell.exe, pwsh.exe, or powershell_ise.exe) has executed any unexpected or unauthorized scripts.
* Check the network logs for the host to identify any unusual or unauthorized outbound RPC connections, particularly those targeting port 135, and verify if the destination addresses are legitimate and expected.
* Investigate the context of the taskschd.dll library load by reviewing recent scheduled tasks on the host to identify any newly created or modified tasks that could be linked to the alert.
* Correlate the alert with other security events or logs from the same host or network segment to identify any patterns or additional indicators of compromise that may suggest lateral movement or remote discovery attempts.

**False positive analysis**

* Legitimate administrative tasks using PowerShell may trigger the rule if they involve loading the Task Scheduler DLL and making RPC connections. To manage this, identify and whitelist specific scripts or processes that are known to perform these actions regularly.
* Automated system maintenance or monitoring tools might also load the Task Scheduler DLL and establish RPC connections. Review these tools and exclude their process IDs or hashes from the detection rule to prevent false alerts.
* Software updates or installations that use PowerShell scripts could mimic the behavior detected by the rule. Monitor update schedules and temporarily disable the rule during these periods if necessary, or create exceptions for known update processes.
* Developers or IT staff using PowerShell for legitimate remote management tasks may inadvertently trigger the rule. Implement user-based exceptions for trusted personnel or restrict the rule to non-administrative accounts to reduce false positives.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further lateral movement or data exfiltration.
* Terminate the suspicious PowerShell process identified in the alert to stop any ongoing malicious activity.
* Conduct a forensic analysis of the affected system to identify any additional malicious scheduled tasks or scripts and remove them.
* Review and clean up any unauthorized scheduled tasks created on the system to ensure no persistence mechanisms remain.
* Reset credentials for any accounts that were used or potentially compromised during the incident to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the attack.
* Implement enhanced monitoring for similar PowerShell and scheduled task activities across the network to detect and respond to future threats promptly.


## Rule query [_rule_query_5809]

```js
sequence by host.id, process.entity_id with maxspan = 5s
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")]
 [network where host.os.type == "windows" and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and destination.port == 135 and not destination.address in ("127.0.0.1", "::1")]
```

**Framework**: MITRE ATT&CKTM

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

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



