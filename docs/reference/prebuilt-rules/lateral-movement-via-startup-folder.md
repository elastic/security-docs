---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/lateral-movement-via-startup-folder.html
---

# Lateral Movement via Startup Folder [lateral-movement-via-startup-folder]

Identifies suspicious file creations in the startup folder of a remote system. An adversary could abuse this to move laterally by dropping a malicious script or executable that will be executed after a reboot or user logon.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.mdsec.co.uk/2017/06/rdpinception/](https://www.mdsec.co.uk/2017/06/rdpinception/)
* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_470]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Lateral Movement via Startup Folder**

The Windows Startup folder is a mechanism that allows programs to run automatically upon user logon or system reboot. Adversaries exploit this by placing malicious files in the Startup folder of remote systems, often accessed via RDP or SMB, to ensure persistence and facilitate lateral movement. The detection rule identifies suspicious file activities in these folders, focusing on processes like mstsc.exe, which may indicate unauthorized access and file creation, signaling potential lateral movement attempts.

**Possible investigation steps**

* Review the alert details to confirm the file creation or change event in the specified Startup folder paths, focusing on the file path patterns: "?:\\Users\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" and "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*".
* Check the process information associated with the event, particularly if the process name is "mstsc.exe" or if the process ID is 4, to determine if the activity is linked to remote access via RDP or SMB.
* Investigate the origin of the remote connection by examining network logs or RDP session logs to identify the source IP address and user account involved in the connection.
* Analyze the newly created or modified file in the Startup folder for malicious characteristics, such as unusual file names, unexpected file types, or known malware signatures, using antivirus or sandbox analysis tools.
* Review user account activity and permissions to determine if the account associated with the process has been compromised or is being misused for unauthorized access.
* Correlate this event with other security alerts or logs from data sources like Sysmon, Microsoft Defender for Endpoint, or SentinelOne to identify any related suspicious activities or patterns indicating lateral movement attempts.

**False positive analysis**

* Legitimate software installations or updates may create files in the Startup folder, triggering the rule. Users can manage this by maintaining a list of known software that typically modifies the Startup folder and creating exceptions for these processes.
* System administrators using remote desktop tools like mstsc.exe for legitimate purposes might inadvertently trigger the rule. To handle this, users can exclude specific administrator accounts or known IP addresses from the detection rule.
* Automated scripts or system management tools that deploy updates or configurations across multiple systems might cause false positives. Users should identify these tools and add them to an exclusion list to prevent unnecessary alerts.
* Some enterprise applications may use the Startup folder for legitimate operations, especially during system boot or user logon. Users should document these applications and configure the rule to ignore file changes associated with them.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further lateral movement and potential spread of the threat.
* Terminate any suspicious processes, particularly those related to mstsc.exe or any unauthorized processes with PID 4, to halt any ongoing malicious activities.
* Remove any unauthorized files or scripts found in the Startup folder paths specified in the detection query to prevent them from executing on reboot or user logon.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and reset credentials for any accounts that were accessed or potentially compromised during the incident to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for RDP and SMB activities, focusing on unusual file creation events in Startup folders, to improve detection of similar threats in the future.


## Rule query [_rule_query_505]

```js
file where host.os.type == "windows" and event.type in ("creation", "change") and

 /* via RDP TSClient mounted share or SMB */
  (process.name : "mstsc.exe" or process.pid == 4) and

   file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Remote Desktop Protocol
    * ID: T1021.001
    * Reference URL: [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)



