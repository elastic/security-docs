---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/delete-volume-usn-journal-with-fsutil.html
---

# Delete Volume USN Journal with Fsutil [delete-volume-usn-journal-with-fsutil]

Identifies use of the fsutil.exe to delete the volume USNJRNL. This technique is used by attackers to eliminate evidence of files created during post-exploitation activities.

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
* logs-crowdstrike.fdr*

**Severity**: low

**Risk score**: 21

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
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_265]

**Triage and analysis**

**Investigating Delete Volume USN Journal with Fsutil**

The Update Sequence Number (USN) Journal is a feature in the NTFS file system used by Microsoft Windows operating systems to keep track of changes made to files and directories on a disk volume. The journal records metadata for changes such as file creation, deletion, modification, and permission changes. It is used by the operating system for various purposes, including backup and recovery, file indexing, and file replication.

This artifact can provide valuable information in forensic analysis, such as programs executed (prefetch file operations), file modification events in suspicious directories, deleted files, etc. Attackers may delete this artifact in an attempt to cover their tracks, and this rule identifies the usage of the `fsutil.exe` utility to accomplish it.

Consider using the Elastic Defend integration instead of USN Journal, as the Elastic Defend integration provides more visibility and context in the file operations it records.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Verify if any other anti-forensics behaviors were observed.
* Review file operation logs from Elastic Defend for suspicious activity the attacker tried to hide.

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_275]

```js
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "deletejournal" and process.args : "usn"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: File Deletion
    * ID: T1070.004
    * Reference URL: [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)



