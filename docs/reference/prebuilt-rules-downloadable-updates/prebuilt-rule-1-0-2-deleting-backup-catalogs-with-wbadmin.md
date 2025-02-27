---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-deleting-backup-catalogs-with-wbadmin.html
---

# Deleting Backup Catalogs with Wbadmin [prebuilt-rule-1-0-2-deleting-backup-catalogs-with-wbadmin]

Identifies use of wbadmin.exe to delete the backup catalog. Ransomware and other malware may do this to prevent system recovery.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1605]

## Triage and analysis

## Investigating Deleting Backup Catalogs with Wbadmin

Windows Server Backup stores the details about your backups (what volumes are backed up and where the backups are
located) in a file called a backup catalog, which ransomware victims can use to recover corrupted backup files.
Deleting these files is a common step in threat actor playbooks.

This rule identifies the deletion of the backup catalog using the `wbadmin.exe` utility.

### Possible investigation steps

- Investigate the script execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Confirm whether the account owner is aware of the operation.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check for similar behavior in other hosts on the environment.
- Check if any files on the host machine have been encrypted.

## False positive analysis

- Administrators can use this command to delete corrupted catalogs, but overall the activity is unlikely to be legitimate.

## Related rules

- Third-party Backup Files Deleted via Unexpected Process - 11ea6bec-ebde-4d71-a8e9-784948f8e3e9
- Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
- Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4
- Volume Shadow Copy Deletion via WMIC - dc9c1f74-dac3-48e3-b47f-eb79db358f57

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent destructive behavior, which is commonly associated with this activity.
- Reset the password of the involved accounts.
- If any other destructive action was identified on the host, it is recommended to prioritize the investigation and look
for ransomware preparation and execution activities.
- If any backups were affected:
  - Perform data recovery locally or restore the backups from replicated copies (cloud, other servers, etc.).

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1854]

```js
process where event.type in ("start", "process_started") and
  (process.name : "wbadmin.exe" or process.pe.original_file_name == "WBADMIN.EXE") and
  process.args : "catalog" and process.args : "delete"
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



