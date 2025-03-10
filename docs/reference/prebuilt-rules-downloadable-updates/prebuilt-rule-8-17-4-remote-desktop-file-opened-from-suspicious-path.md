---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-remote-desktop-file-opened-from-suspicious-path.html
---

# Remote Desktop File Opened from Suspicious Path [prebuilt-rule-8-17-4-remote-desktop-file-opened-from-suspicious-path]

Identifies attempts to open a remote desktop file from suspicious paths. Adversaries may abuse RDP files for initial access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)
* [https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/](https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/)
* [https://shorsec.io/blog/malrdp-implementing-rouge-rdp-manually/](https://shorsec.io/blog/malrdp-implementing-rouge-rdp-manually/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Command and Control
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4870]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Remote Desktop File Opened from Suspicious Path**

Remote Desktop Protocol (RDP) allows users to connect to and control a computer remotely, facilitating remote work and administration. However, adversaries can exploit RDP files, which store connection settings, to gain unauthorized access. They may distribute malicious RDP files via phishing, placing them in suspicious directories. The detection rule identifies when RDP files are opened from unusual paths, signaling potential misuse and enabling analysts to investigate further.

**Possible investigation steps**

* Review the process execution details to confirm the presence of "mstsc.exe" and verify the suspicious path from which the RDP file was opened, as specified in the query.
* Check the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears anomalous.
* Investigate the source of the RDP file by examining recent email activity or downloads to identify potential phishing attempts or unauthorized file transfers.
* Analyze the system’s event logs for any other unusual activities or processes that occurred around the same time as the RDP file execution.
* Assess the network connections established by the system during the time of the alert to identify any suspicious or unauthorized remote connections.
* Consult threat intelligence sources to determine if the identified path or file name pattern is associated with known malicious campaigns or threat actors.

**False positive analysis**

* Users frequently download legitimate RDP files from trusted sources like corporate emails or internal portals. To manage this, create exceptions for known safe domains or email addresses in your security tools.
* Temporary directories often store RDP files during legitimate software installations or updates. Monitor these activities and whitelist specific processes or software that are known to use RDP files during their operations.
* Employees working remotely may use RDP files stored in their Downloads folder for legitimate access to company resources. Implement a policy to educate users on safe RDP file handling and consider excluding the Downloads folder from alerts if it is a common practice.
* Some business applications may generate RDP files in temporary directories as part of their normal operation. Identify these applications and configure your detection systems to exclude their specific file paths or process names.
* Automated scripts or IT management tools might use RDP files for routine administrative tasks. Document these scripts and tools, and adjust your detection rules to ignore their specific activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any active RDP sessions initiated from the suspicious paths identified in the alert to cut off potential attacker access.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious files or software.
* Review and remove any unauthorized RDP files from the suspicious directories listed in the detection query to prevent future misuse.
* Reset credentials for any accounts that were used to open the suspicious RDP files, ensuring that new passwords are strong and unique.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and logging for RDP activities across the network to detect and respond to similar threats more effectively in the future.


## Rule query [_rule_query_5825]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.name : "mstsc.exe" and
 process.args : ("?:\\Users\\*\\Downloads\\*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\7z*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*\\*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\BNZ.*.rdp",
                 "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\*.rdp")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



