---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-print-spooler-file-deletion.html
---

# Suspicious Print Spooler File Deletion [suspicious-print-spooler-file-deletion]

Detects deletion of print driver files by an unusual process. This may indicate a clean up attempt post successful privilege escalation via Print Spooler service related vulnerabilities.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 308

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1019]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Print Spooler File Deletion**

The Print Spooler service in Windows manages print jobs and interactions with printers. Adversaries exploit vulnerabilities in this service to escalate privileges, often deleting print driver files to cover their tracks. The detection rule identifies unusual deletions of these files by processes other than legitimate ones, signaling potential misuse and aiding in early threat detection.

**Possible investigation steps**

* Review the alert details to identify the specific file path and name of the deleted DLL file within "C:\Windows\System32\spool\drivers\x64\3\".
* Examine the process responsible for the deletion by checking the process name and its parent process to determine if it is a known legitimate process or a potentially malicious one.
* Investigate the timeline of events around the deletion to identify any preceding or subsequent suspicious activities, such as privilege escalation attempts or unauthorized access.
* Check for any recent vulnerabilities or exploits related to the Print Spooler service that might have been leveraged in this context.
* Correlate the event with other security logs and alerts from data sources like Sysmon, Microsoft Defender for Endpoint, or SentinelOne to gather additional context and confirm the presence of malicious activity.
* Assess the affected system for any signs of compromise or persistence mechanisms that may have been established following the deletion event.

**False positive analysis**

* System maintenance or updates may trigger legitimate deletions of print driver files. Monitor scheduled maintenance activities and correlate them with detected events to confirm legitimacy.
* Third-party printer management software might delete or update driver files as part of its normal operation. Identify and whitelist these processes if they are verified as non-threatening.
* Custom scripts or administrative tools used by IT staff for printer management could inadvertently match the rule’s criteria. Review and document these tools, then create exceptions for known safe operations.
* Automated deployment tools that update or clean up printer drivers across the network might cause false positives. Ensure these tools are recognized and excluded from the detection rule if they are part of routine operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified as responsible for the deletion of print driver files, ensuring they are not legitimate system processes.
* Restore the deleted print driver files from a known good backup to ensure the Print Spooler service functions correctly.
* Conduct a thorough review of user accounts and privileges on the affected system to identify and revoke any unauthorized privilege escalations.
* Apply the latest security patches and updates to the Print Spooler service and related components to mitigate known vulnerabilities.
* Monitor the affected system and network for any signs of further suspicious activity, focusing on similar file deletion patterns or privilege escalation attempts.
* Escalate the incident to the security operations center (SOC) or relevant IT security team for further investigation and to assess the need for broader organizational response measures.


## Rule query [_rule_query_1069]

```js
file where host.os.type == "windows" and event.type == "deletion" and
  file.extension : "dll" and file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll" and
  not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



