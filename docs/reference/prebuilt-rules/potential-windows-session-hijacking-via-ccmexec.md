---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-windows-session-hijacking-via-ccmexec.html
---

# Potential Windows Session Hijacking via CcmExec [potential-windows-session-hijacking-via-ccmexec]

This detection rule identifies when *SCNotification.exe* loads an untrusted DLL, which is a potential indicator of an attacker attempt to hijack/impersonate a Windows user session.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec](https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec)
* [https://mayfly277.github.io/posts/SCCM-LAB-part0x3/#impersonate-users---revshell-connected-users](https://mayfly277.github.io/posts/SCCM-LAB-part0x3/#impersonate-users---revshell-connected-users)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_790]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Windows Session Hijacking via CcmExec**

CcmExec, part of Microsoft’s System Center Configuration Manager, manages client configurations and software updates. Adversaries may exploit it by loading malicious DLLs into SCNotification.exe, a process associated with user notifications. This detection rule identifies suspicious DLL activity, such as recent file creation or modification and untrusted signatures, indicating potential session hijacking attempts.

**Possible investigation steps**

* Review the alert details to confirm that the process name is SCNotification.exe and check the associated DLL file’s creation or modification times to ensure they match the query conditions.
* Investigate the untrusted DLL by examining its file path, hash, and any available metadata to determine its origin and legitimacy.
* Check the code signature status of the DLL to understand why it is marked as untrusted and verify if it has been tampered with or is from an unknown publisher.
* Analyze recent system logs and user activity around the time the DLL was loaded to identify any suspicious behavior or unauthorized access attempts.
* Correlate the alert with other security events or alerts from the same host to identify potential patterns or related incidents that could indicate a broader attack.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they involve recent DLL file creation or modification. Users can create exceptions for known software update processes to prevent unnecessary alerts.
* System maintenance activities, such as patch management or configuration changes, might cause SCNotification.exe to load new DLLs. Exclude these activities by identifying and whitelisting trusted maintenance operations.
* Custom or in-house applications that are not signed by a recognized authority may be flagged. Ensure these applications are signed with a trusted certificate or add them to an allowlist to avoid false positives.
* Security tools or monitoring software that interact with SCNotification.exe could be mistakenly identified. Verify these tools and exclude them from the rule if they are deemed safe and necessary for operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the attacker.
* Terminate the SCNotification.exe process to stop the execution of the untrusted DLL and prevent further malicious activity.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious files or software.
* Review and restore any modified or corrupted system files from a known good backup to ensure system integrity.
* Investigate the source of the untrusted DLL and remove any unauthorized software or scripts that may have facilitated its introduction.
* Implement application whitelisting to prevent unauthorized DLLs from being loaded by SCNotification.exe or other critical processes in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_838]

```js
library where host.os.type == "windows" and process.name : "SCNotification.exe" and
  (dll.Ext.relative_file_creation_time < 86400 or dll.Ext.relative_file_name_modify_time <= 500) and dll.code_signature.status != "trusted"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)



