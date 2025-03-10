---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/third-party-backup-files-deleted-via-unexpected-process.html
---

# Third-party Backup Files Deleted via Unexpected Process [third-party-backup-files-deleted-via-unexpected-process]

Identifies the deletion of backup files, saved using third-party software, by a process outside of the backup suite. Adversaries may delete Backup files to ensure that recovery from a ransomware attack is less likely.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love](https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1075]

**Triage and analysis**

**Investigating Third-party Backup Files Deleted via Unexpected Process**

Backups are a significant obstacle for any ransomware operation. They allow the victim to resume business by performing data recovery, making them a valuable target.

Attackers can delete backups from the host and gain access to backup servers to remove centralized backups for the environment, ensuring that victims have no alternatives to paying the ransom.

This rule identifies file deletions performed by a process that does not belong to the backup suite and aims to delete Veritas or Veeam backups.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Check if any files on the host machine have been encrypted.

**False positive analysis**

* This rule can be triggered by the manual removal of backup files and by removal using other third-party tools that are not from the backup suite. Exceptions can be added for specific accounts and executables, preferably tied together.

**Related rules**

* Deleting Backup Catalogs with Wbadmin - 581add16-df76-42bb-af8e-c979bfb39a59
* Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
* Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4
* Volume Shadow Copy Deletion via WMIC - dc9c1f74-dac3-48e3-b47f-eb79db358f57

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Consider isolating the involved host to prevent destructive behavior, which is commonly associated with this activity.
* Perform data recovery locally or restore the backups from replicated copies (Cloud, other servers, etc.).
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_680]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1130]

```js
file where host.os.type == "windows" and event.type == "deletion" and
  (
    /* Veeam Related Backup Files */
    (
      file.extension : ("VBK", "VIB", "VBM") and
      not (
        process.executable : ("?:\\Windows\\*", "?:\\Program Files\\*", "?:\\Program Files (x86)\\*") and
        (process.code_signature.trusted == true and process.code_signature.subject_name : ("Veeam Software Group GmbH", "Veeam Software AG"))
      )
    ) or
    /* Veritas Backup Exec Related Backup File */
    (
      file.extension : "BKF" and
        not process.executable : (
          "?:\\Program Files\\Veritas\\Backup Exec\\*",
          "?:\\Program Files (x86)\\Veritas\\Backup Exec\\*"
        )
    )
  ) and
  not (
    process.name : ("MSExchangeMailboxAssistants.exe", "Microsoft.PowerBI.EnterpriseGateway.exe") and
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
  ) and
  not file.path : (
    "?:\\ProgramData\\Trend Micro\\*",
    "?:\\Program Files (x86)\\Trend Micro\\*",
    "?:\\$RECYCLE.BIN\\*"
  )
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



