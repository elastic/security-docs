---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-third-party-backup-files-deleted-via-unexpected-process.html
---

# Third-party Backup Files Deleted via Unexpected Process [prebuilt-rule-8-3-2-third-party-backup-files-deleted-via-unexpected-process]

Identifies the deletion of backup files, saved using third-party software, by a process outside of the backup suite. Adversaries may delete Backup files to ensure that recovery from a ransomware attack is less likely.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love](https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2509]

## Triage and analysis

## Investigating Third-party Backup Files Deleted via Unexpected Process

Backups are a significant obstacle for any ransomware operation. They allow the victim to resume business by performing
data recovery, making them a valuable target.

Attackers can delete backups from the host and gain access to backup servers to remove centralized backups for the
environment, ensuring that victims have no alternatives to paying the ransom.

This rule identifies file deletions performed by a process that does not belong to the backup suite and aims to delete
Veritas or Veeam backups.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check if any files on the host machine have been encrypted.

## False positive analysis

- This rule can be triggered by the manual removal of backup files and by removal using other third-party tools that are
not from the backup suite. Exceptions can be added for specific accounts and executables, preferably tied together.

## Related rules

- Deleting Backup Catalogs with Wbadmin - 581add16-df76-42bb-af8e-c979bfb39a59
- Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
- Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4
- Volume Shadow Copy Deletion via WMIC - dc9c1f74-dac3-48e3-b47f-eb79db358f57

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Consider isolating the involved host to prevent destructive behavior, which is commonly associated with this activity.
- Perform data recovery locally or restore the backups from replicated copies (Cloud, other servers, etc.).
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2882]

```js
file where event.type == "deletion" and
  (
  /* Veeam Related Backup Files */
  (file.extension : ("VBK", "VIB", "VBM") and
  not process.executable : ("?:\\Windows\\Veeam\\Backup\\*",
                            "?:\\Program Files\\Veeam\\Backup and Replication\\*",
                            "?:\\Program Files (x86)\\Veeam\\Backup and Replication\\*")) or

  /* Veritas Backup Exec Related Backup File */
  (file.extension : "BKF" and
  not process.executable : ("?:\\Program Files\\Veritas\\Backup Exec\\*",
                            "?:\\Program Files (x86)\\Veritas\\Backup Exec\\*"))
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Inhibit System Recovery
    * ID: T1490
    * Reference URL: [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)



