---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-remote-file-copy-to-a-hidden-share.html
---

# Remote File Copy to a Hidden Share [prebuilt-rule-8-17-4-remote-file-copy-to-a-hidden-share]

Identifies a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
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

**References**:

* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
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

## Investigation guide [_investigation_guide_4893]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Remote File Copy to a Hidden Share**

In Windows environments, hidden network shares are often used for legitimate administrative tasks, allowing file transfers without user visibility. However, adversaries can exploit these shares for lateral movement or data exfiltration. The detection rule identifies suspicious file copy attempts using common command-line tools like cmd.exe and powershell.exe, focusing on hidden share patterns to flag potential threats.

**Possible investigation steps**

* Review the process details to identify the specific command-line tool used (cmd.exe, powershell.exe, xcopy.exe, or robocopy.exe) and examine the arguments to understand the nature of the file copy operation.
* Investigate the source and destination of the file copy by analyzing the network share path in the process arguments, focusing on the hidden share pattern (e.g., \*\\*$).
* Check the user account associated with the process to determine if it has legitimate access to the hidden share and assess if the activity aligns with the user’s typical behavior.
* Correlate the event with other logs or alerts from the same host or user to identify any additional suspicious activities, such as unusual login attempts or privilege escalation.
* Examine the historical activity of the involved host to identify any previous instances of similar file copy attempts or other indicators of lateral movement.
* Consult threat intelligence sources to determine if the detected pattern or tools are associated with known adversary techniques or campaigns.

**False positive analysis**

* Administrative tasks using hidden shares can trigger alerts. Regularly review and document legitimate administrative activities that involve file transfers to hidden shares.
* Backup operations often use hidden shares for data storage. Identify and exclude backup processes by specifying known backup software and their typical command-line arguments.
* Software deployment tools may utilize hidden shares for distributing updates. Create exceptions for recognized deployment tools by listing their process names and associated arguments.
* IT maintenance scripts might copy files to hidden shares for system updates. Maintain a list of approved maintenance scripts and exclude them from triggering alerts.
* User-initiated file transfers for legitimate purposes can be mistaken for threats. Educate users on proper file transfer methods and monitor for unusual patterns that deviate from documented procedures.

**Response and remediation**

* Isolate the affected system from the network to prevent further lateral movement or data exfiltration.
* Terminate any suspicious processes identified in the alert, such as cmd.exe, powershell.exe, xcopy.exe, or robocopy.exe, that are involved in the file copy attempt.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise or unauthorized access.
* Change credentials for any accounts that were used in the suspicious activity to prevent further unauthorized access.
* Review and restrict permissions on network shares, especially hidden shares, to ensure only authorized users have access.
* Monitor network traffic for any further suspicious activity related to hidden shares and lateral movement attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Rule query [_rule_query_5848]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("cmd.exe", "powershell.exe", "xcopy.exe") and
    process.args : ("copy*", "move*", "cp", "mv") or
    process.name : "robocopy.exe"
  ) and process.args : "*\\\\*\\*$*"
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

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)



