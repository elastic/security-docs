---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-ransomware-note-file-dropped-via-smb.html
---

# Potential Ransomware Note File Dropped via SMB [potential-ransomware-note-file-dropped-via-smb]

Identifies an incoming SMB connection followed by the creation of a file with a name similar to ransomware note files. This may indicate a remote ransomware attack via the SMB protocol.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_753]

**Triage and analysis**

**Performance**

* This rule may cause medium to high performance impact due to logic scoping all icoming SMB network events.

**Possible investigation steps**

* Investigate the source.ip address connecting to port 445 on this host.
* Identify the user account that performed the file creation via SMB.
* If the number of files is too high and source.ip connecting over SMB is unusual isolate the host and block the used credentials.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* Remote file creation with similar file naming convention via SMB.

**Related rules**

* Third-party Backup Files Deleted via Unexpected Process - 11ea6bec-ebde-4d71-a8e9-784948f8e3e9
* Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
* Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4
* Volume Shadow Copy Deletion via WMIC - dc9c1f74-dac3-48e3-b47f-eb79db358f57
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


## Rule query [_rule_query_801]

```js
sequence by host.id with maxspan=1s
 [network where host.os.type == "windows" and
  event.action == "connection_accepted" and destination.port == 445 and source.port >= 49152 and process.pid == 4 and
  source.ip != "127.0.0.1" and source.ip != "::1" and
  network.type == "ipv4" and not endswith(source.address, destination.address)]
 [file where host.os.type == "windows" and event.action == "creation" and
  process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-*") and file.extension : ("hta", "txt", "readme", "htm*") and
  file.path : "C:\\Users\\*" and
   /* ransom file name keywords */
    file.name : ("*read*me*", "*lock*", "*@*", "*RECOVER*", "*decrypt*", "*restore*file*", "*FILES_BACK*", "*how*to*")] with runs=3
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

* Technique:

    * Name: Inhibit System Recovery
    * ID: T1490
    * Reference URL: [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)

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



