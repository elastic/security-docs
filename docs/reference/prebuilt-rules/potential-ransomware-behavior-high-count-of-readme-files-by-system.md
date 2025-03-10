---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-ransomware-behavior-high-count-of-readme-files-by-system.html
---

# Potential Ransomware Behavior - High count of Readme files by System [potential-ransomware-behavior-high-count-of-readme-files-by-system]

This rule identifies a high number (20) of file creation event by the System virtual process from the same host and with same file name containing keywords similar to ransomware note files and all within a short time period.

**Rule type**: threshold

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

* [https://news.sophos.com/en-us/2023/12/21/akira-again-the-ransomware-that-keeps-on-taking/](https://news.sophos.com/en-us/2023/12/21/akira-again-the-ransomware-that-keeps-on-taking/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_752]

**Triage and analysis**

**Possible investigation steps**

* Investigate the content of the readme files.
* Investigate any file names with unusual extensions.
* Investigate any incoming network connection to port 445 on this host.
* Investigate any network logon events to this host.
* Identify the total number and type of modified files by pid 4.
* If the number of files is too high and source.ip connecting over SMB is unusual isolate the host and block the used credentials.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* Local file modification from a Kernel mode driver.

**Related rules**

* Third-party Backup Files Deleted via Unexpected Process - 11ea6bec-ebde-4d71-a8e9-784948f8e3e9
* Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
* Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4
* Volume Shadow Copy Deletion via WMIC - dc9c1f74-dac3-48e3-b47f-eb79db358f57
* Potential Ransomware Note File Dropped via SMB - 02bab13d-fb14-4d7c-b6fe-4a28874d37c5
* Suspicious File Renamed via SMB - 78e9b5d5-7c07-40a7-a591-3dbbf464c386

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Consider isolating the involved host to prevent destructive behavior, which is commonly associated with this activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* If any other destructive action was identified on the host, it is recommended to prioritize the investigation and look for ransomware preparation and execution activities.
* If any backups were affected:
* Perform data recovery locally or restore the backups from replicated copies (cloud, other servers, etc.).
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_800]

```js
event.category:file and host.os.type:windows and process.pid:4 and event.action:creation and
 file.name:(*read*me* or *README* or *lock* or *LOCK* or *how*to* or *HOW*TO* or *@* or *recover* or *RECOVER* or *decrypt* or *DECRYPT* or *restore* or *RESTORE* or *FILES_BACK* or *files_back*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)

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



