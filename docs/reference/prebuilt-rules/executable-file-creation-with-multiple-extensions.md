---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/executable-file-creation-with-multiple-extensions.html
---

# Executable File Creation with Multiple Extensions [executable-file-creation-with-multiple-extensions]

Masquerading can allow an adversary to evade defenses and better blend in with the environment. One way it occurs is when the name or location of a file is manipulated as a means of tricking a user into executing what they think is a benign file type but is actually executable code.

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

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_306]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Executable File Creation with Multiple Extensions**

In Windows environments, adversaries may exploit file extensions to disguise malicious executables as benign files, such as documents or images, by appending multiple extensions. This tactic, known as masquerading, aims to deceive users and evade security measures. The detection rule identifies suspicious file creations by monitoring for executables with misleading extensions, excluding known legitimate processes, thus highlighting potential threats.

**Possible investigation steps**

* Review the file creation event details to identify the full file path and name, focusing on the extensions used to determine if they match the suspicious pattern outlined in the query.
* Investigate the process that created the file by examining the process.executable field to determine if it is a known legitimate process or potentially malicious.
* Check the file’s origin by analyzing the user account and network activity associated with the file creation event to identify any unusual or unauthorized access patterns.
* Utilize threat intelligence sources to assess if the file hash or any related indicators of compromise (IOCs) are known to be associated with malicious activity.
* Examine the file’s metadata and properties to verify its authenticity and check for any signs of tampering or unusual characteristics.
* Conduct a behavioral analysis of the file in a controlled environment to observe any malicious actions or network communications it may attempt.

**False positive analysis**

* Legitimate software installations may create executables with multiple extensions during setup processes. Users can exclude these by adding exceptions for known installer paths, such as "C:\Users*\QGIS_SCCM\Files\QGIS-OSGeo4W-*-Setup-x86_64.exe".
* System updates or patches might temporarily create files with multiple extensions. Monitor and verify these activities, and if confirmed as legitimate, add exceptions for the specific update processes.
* Development environments or script-based applications may generate files with multiple extensions for testing purposes. Identify these environments and exclude their specific file paths or processes to prevent false positives.
* Security tools or administrative scripts might use multiple extensions for legitimate purposes. Review and whitelist these tools by their executable paths or process names to avoid unnecessary alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate any suspicious processes associated with the masquerading executable files to halt any ongoing malicious actions.
* Quarantine the identified files with multiple extensions to prevent execution and further analysis.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional threats.
* Review and restore any altered system configurations or files to their original state to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for similar file creation activities to improve detection and response capabilities for future incidents.


## Rule query [_rule_query_320]

```js
file where host.os.type == "windows" and event.type == "creation" and file.extension : "exe" and
  file.name regex~ """.*\.(vbs|vbe|bat|js|cmd|wsh|ps1|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso)\.exe""" and
  not (process.executable : ("?:\\Windows\\System32\\msiexec.exe", "C:\\Users\\*\\QGIS_SCCM\\Files\\QGIS-OSGeo4W-*-Setup-x86_64.exe") and
       file.path : "?:\\Program Files\\QGIS *\\apps\\grass\\*.exe")
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

    * Name: Double File Extension
    * ID: T1036.007
    * Reference URL: [https://attack.mitre.org/techniques/T1036/007/](https://attack.mitre.org/techniques/T1036/007/)

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



