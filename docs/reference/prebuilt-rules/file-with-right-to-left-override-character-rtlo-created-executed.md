---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-with-right-to-left-override-character-rtlo-created-executed.html
---

# File with Right-to-Left Override Character (RTLO) Created/Executed [file-with-right-to-left-override-character-rtlo-created-executed]

Identifies the creation or execution of files or processes with names containing the Right-to-Left Override (RTLO) character, which can be used to disguise the file extension and trick users into executing malicious files.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_338]

**Triage and analysis**

[TBC: QUOTE]
**Investigating File with Right-to-Left Override Character (RTLO) Created/Executed**

The RTLO character reverses text direction, often used to disguise file extensions, making malicious files appear benign. Adversaries exploit this to trick users into executing harmful files. The detection rule identifies suspicious file or process activities on Windows systems by scanning for RTLO characters in file paths or process names, helping to uncover potential masquerading attempts.

**Possible investigation steps**

* Review the alert details to identify the specific file path or process name containing the RTLO character by examining the file.path or process.name fields.
* Check the event.type field to determine whether the alert was triggered by a file creation or process start event, which can help prioritize the investigation focus.
* Investigate the origin of the file or process by examining the file’s creation time, user account involved, and any associated network activity to identify potential sources or delivery methods.
* Analyze the file or process for malicious behavior by using endpoint detection tools or sandbox environments to execute and monitor its actions.
* Cross-reference the file or process with threat intelligence databases to check for known malicious indicators or similar attack patterns.
* Review system logs and other security alerts around the same timeframe to identify any additional suspicious activities or related incidents.

**False positive analysis**

* Legitimate software installations or updates may use RTLO characters in file names to manage versioning or localization, which can trigger false positives. Users can create exceptions for known software vendors or specific installation directories to reduce these alerts.
* Some file management or backup applications might use RTLO characters in temporary file names for internal processing. Identifying these applications and excluding their specific file paths from monitoring can help minimize false positives.
* Custom scripts or tools developed in-house might inadvertently use RTLO characters for legitimate purposes. Reviewing these scripts and excluding their execution paths or file names from the detection rule can prevent unnecessary alerts.
* Certain international or multilingual applications may use RTLO characters as part of their normal operation. Users should identify these applications and configure exceptions based on their file paths or process names to avoid false positives.
* In environments where file names are dynamically generated and may include RTLO characters, consider implementing a whitelist of trusted file paths or process names to reduce the likelihood of false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes identified with the RTLO character in their names to halt any ongoing malicious activity.
* Quarantine the files containing the RTLO character to prevent execution and further analysis.
* Conduct a thorough scan of the isolated system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and analyze system logs and security alerts to determine the extent of the compromise and identify any lateral movement or additional affected systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional containment measures are necessary.
* Implement enhanced monitoring and detection rules to identify future attempts to use RTLO characters for masquerading, ensuring that similar threats are detected promptly.


## Rule query [_rule_query_360]

```js
any where host.os.type == "windows" and event.category in ("file", "process") and
  (
    (event.type == "creation" and file.path : "*\u{202E}*") or
    (event.type == "start" and process.name : "*\u{202E}*")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Right-to-Left Override
    * ID: T1036.002
    * Reference URL: [https://attack.mitre.org/techniques/T1036/002/](https://attack.mitre.org/techniques/T1036/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



