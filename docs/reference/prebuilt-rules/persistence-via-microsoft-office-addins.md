---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-microsoft-office-addins.html
---

# Persistence via Microsoft Office AddIns [persistence-via-microsoft-office-addins]

Detects attempts to establish persistence on an endpoint by abusing Microsoft Office add-ins.

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

* [https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence](https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 309

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_624]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Microsoft Office AddIns**

Microsoft Office AddIns enhance productivity by allowing custom functionalities in Office applications. However, adversaries exploit this by placing malicious add-ins in specific startup directories, ensuring execution each time the application launches. The detection rule identifies suspicious files with extensions like .xll or .xlam in these directories, flagging potential persistence mechanisms on Windows systems.

**Possible investigation steps**

* Review the file path and extension from the alert to confirm it matches the suspicious directories and extensions specified in the detection rule, such as .xll or .xlam in the Microsoft Office startup directories.
* Check the file creation and modification timestamps to determine when the suspicious file was added or altered, which can help establish a timeline of potential malicious activity.
* Investigate the file’s origin by examining recent file downloads, email attachments, or network activity that might have introduced the file to the system.
* Analyze the file’s contents or hash against known malware databases to identify if it is a known threat or potentially malicious.
* Review user activity and system logs around the time the file was created or modified to identify any unusual behavior or processes that could be related to the persistence mechanism.
* Assess the impacted user’s role and access level to determine the potential risk and impact of the persistence mechanism on the organization.

**False positive analysis**

* Legitimate add-ins installed by trusted software vendors may trigger alerts. Verify the source and publisher of the add-in to determine its legitimacy.
* Custom add-ins developed internally for business purposes can be flagged. Maintain a whitelist of known internal add-ins to prevent unnecessary alerts.
* Frequent updates to legitimate add-ins might cause repeated alerts. Implement version control and update the whitelist accordingly to accommodate these changes.
* User-specific add-ins for accessibility or productivity tools may be detected. Educate users on safe add-in practices and monitor for any unusual behavior.
* Temporary add-ins used for specific projects or tasks can be mistaken for threats. Document and review these cases to ensure they are recognized as non-threatening.

**Response and remediation**

* Isolate the affected endpoint from the network to prevent further spread of the potential threat.
* Terminate any suspicious Microsoft Office processes that may be running add-ins from the identified directories.
* Remove the malicious add-in files from the specified startup directories: "C:\Users*\AppData\Roaming\Microsoft\Word\Startup\", "C:\Users\*\AppData\Roaming\Microsoft\AddIns\", and "C:\Users\*\AppData\Roaming\Microsoft\Excel\XLSTART\".
* Conduct a full antivirus and antimalware scan on the affected system using tools like Microsoft Defender for Endpoint to ensure no other malicious files are present.
* Review and restore any altered system configurations or settings to their default state to ensure system integrity.
* Monitor the affected system and network for any signs of re-infection or related suspicious activity, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations center (SOC) or relevant IT security team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_666]

```js
file where host.os.type == "windows" and event.type != "deletion" and
 file.extension : ("wll","xll","ppa","ppam","xla","xlam") and
 file.path :
    (
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)

* Sub-technique:

    * Name: Add-ins
    * ID: T1137.006
    * Reference URL: [https://attack.mitre.org/techniques/T1137/006/](https://attack.mitre.org/techniques/T1137/006/)



