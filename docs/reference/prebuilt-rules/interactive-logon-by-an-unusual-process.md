---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/interactive-logon-by-an-unusual-process.html
---

# Interactive Logon by an Unusual Process [interactive-logon-by-an-unusual-process]

Identifies interactive logon attempt with alternate credentials and by an unusual process. Adversaries may create a new token to escalate privileges and bypass access controls.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: System
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_438]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Interactive Logon by an Unusual Process**

Interactive logons in Windows environments typically involve standard processes like winlogon.exe. Adversaries may exploit alternate processes to create tokens, escalating privileges and bypassing controls. This detection rule identifies anomalies by flagging logons via non-standard executables, focusing on mismatched user SIDs and unusual process paths, thus highlighting potential privilege escalation attempts.

**Possible investigation steps**

* Review the process executable path to determine if it is a known or expected application for interactive logons. Investigate any unfamiliar or suspicious paths.
* Examine the SubjectUserSid and TargetUserSid to identify the users involved in the logon attempt. Check for any discrepancies or unusual patterns in user activity.
* Analyze the event logs around the time of the alert to identify any related or preceding events that might indicate how the unusual process was initiated.
* Investigate the system for any signs of compromise, such as unexpected changes in system files, unauthorized software installations, or other indicators of malicious activity.
* Check for any recent privilege escalation attempts or access token manipulations that might correlate with the alert, using the MITRE ATT&CK framework references for guidance.

**False positive analysis**

* Legitimate administrative tools or scripts may trigger this rule if they use non-standard executables for logon processes. To manage this, identify and whitelist these known tools by adding their executable paths to the exception list.
* Custom applications developed in-house that require interactive logon might be flagged. Review these applications and, if verified as safe, exclude their executable paths from the detection rule.
* Automated tasks or services that use alternate credentials for legitimate purposes can cause false positives. Analyze these tasks and, if they are part of regular operations, adjust the rule to exclude their specific user SIDs or executable paths.
* Security software or monitoring tools that perform logon actions for scanning or auditing purposes may be incorrectly flagged. Confirm their legitimacy and add them to the exception list to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified as executing from non-standard paths that are not part of the legitimate Windows system processes.
* Revoke any tokens or credentials associated with the anomalous logon session to prevent further misuse.
* Conduct a thorough review of user accounts involved, focusing on any unauthorized privilege escalations or changes in permissions, and reset passwords as necessary.
* Analyze the system for any signs of persistence mechanisms or additional malware, and remove any identified threats.
* Restore the system from a known good backup if any unauthorized changes or malware are detected that cannot be easily remediated.
* Report the incident to the appropriate internal security team or management for further investigation and potential escalation to law enforcement if necessary.


## Setup [_setup_275]

**Setup**

Audit event 4624 is needed to trigger this rule.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_473]

```js
authentication where
 host.os.type : "windows" and winlog.event_data.LogonProcessName : "Advapi*" and
 winlog.logon.type == "Interactive" and winlog.event_data.SubjectUserSid : ("S-1-5-21*", "S-1-12-*") and
 winlog.event_data.TargetUserSid : ("S-1-5-21*", "S-1-12-*")  and process.executable : "C:\\*" and
 not startswith~(winlog.event_data.SubjectUserSid, winlog.event_data.TargetUserSid) and
 not process.executable :
            ("?:\\Windows\\System32\\winlogon.exe",
             "?:\\Windows\\System32\\wininit.exe",
             "?:\\Program Files\\*.exe",
             "?:\\Program Files (x86)\\*.exe",
             "?:\\Windows\\SysWOW64\\inetsrv\\w3wp.exe",
             "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
             "?:\\Windows\\SysWOW64\\msiexec.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Create Process with Token
    * ID: T1134.002
    * Reference URL: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

* Sub-technique:

    * Name: Make and Impersonate Token
    * ID: T1134.003
    * Reference URL: [https://attack.mitre.org/techniques/T1134/003/](https://attack.mitre.org/techniques/T1134/003/)



