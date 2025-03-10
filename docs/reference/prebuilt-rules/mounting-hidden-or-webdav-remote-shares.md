---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/mounting-hidden-or-webdav-remote-shares.html
---

# Mounting Hidden or WebDav Remote Shares [mounting-hidden-or-webdav-remote-shares]

Identifies the use of net.exe to mount a WebDav or hidden remote share. This may indicate lateral movement or preparation for data exfiltration.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Lateral Movement
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

## Investigation guide [_investigation_guide_550]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Mounting Hidden or WebDav Remote Shares**

WebDav and hidden remote shares facilitate file sharing and collaboration across networks, often used in enterprise environments. Adversaries exploit these to move laterally or exfiltrate data by mounting shares using tools like net.exe. The detection rule identifies suspicious share mounts by monitoring specific command patterns, excluding benign operations, to flag potential threats.

**Possible investigation steps**

* Review the process details to confirm the use of net.exe or net1.exe for mounting shares, focusing on the process.name and process.pe.original_file_name fields.
* Examine the process.args field to identify the specific share being accessed, noting any patterns like "\\\*\\*$**", "\\\\**@SSL\*", or "http*" that indicate hidden or WebDav shares.
* Check the parent process information to determine if net1.exe was executed independently or as a child of another suspicious process, which could suggest malicious intent.
* Investigate the user account associated with the process to verify if the activity aligns with their typical behavior or if it appears anomalous.
* Correlate the event with other logs or alerts from the same host or user to identify any patterns of lateral movement or data exfiltration attempts.
* Assess the network activity around the time of the alert to detect any unusual outbound connections that might indicate data exfiltration.

**False positive analysis**

* Legitimate use of net.exe for mounting network drives in enterprise environments can trigger false positives. Users can create exceptions for known internal IP addresses or specific user accounts frequently performing these actions.
* Automated scripts or system processes that use net.exe to connect to WebDav or hidden shares for legitimate purposes may be flagged. Identify these scripts and processes, and exclude them by their process hash or command line patterns.
* Regular operations involving OneDrive or other cloud-based services might be misidentified as suspicious. Exclude these by specifying known service URLs or domains in the detection rule.
* Administrative tasks involving network share management can be mistaken for threats. Document and exclude these tasks by correlating them with scheduled maintenance windows or specific admin user accounts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further lateral movement or data exfiltration.
* Terminate any suspicious processes related to net.exe or net1.exe that are actively mounting hidden or WebDav shares.
* Conduct a thorough review of recent file access and transfer logs to identify any unauthorized data access or exfiltration attempts.
* Change credentials for any accounts that were used in the suspicious activity to prevent further unauthorized access.
* Implement network segmentation to limit access to critical systems and sensitive data, reducing the risk of lateral movement.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Enhance monitoring and alerting for similar activities by ensuring that all relevant security tools are configured to detect and alert on suspicious use of net.exe and net1.exe.


## Rule query [_rule_query_591]

```js
process where host.os.type == "windows" and event.type == "start" and
 ((process.name : "net.exe" or ?process.pe.original_file_name == "net.exe") or ((process.name : "net1.exe" or ?process.pe.original_file_name == "net1.exe") and
 not process.parent.name : "net.exe")) and
 process.args : "use" and
 /* including hidden and webdav based online shares such as onedrive  */
 process.args : ("\\\\*\\*$*", "\\\\*@SSL\\*", "http*") and
 /* excluding shares deletion operation */
 not process.args : "/d*"
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

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)

* Sub-technique:

    * Name: Domain Account
    * ID: T1087.002
    * Reference URL: [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)



