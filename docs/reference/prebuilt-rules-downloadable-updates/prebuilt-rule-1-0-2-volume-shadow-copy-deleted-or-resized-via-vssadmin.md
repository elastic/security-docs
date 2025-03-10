---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-volume-shadow-copy-deleted-or-resized-via-vssadmin.html
---

# Volume Shadow Copy Deleted or Resized via VssAdmin [prebuilt-rule-1-0-2-volume-shadow-copy-deleted-or-resized-via-vssadmin]

Identifies use of vssadmin.exe for shadow copy deletion or resizing on endpoints. This commonly occurs in tandem with ransomware or other destructive attacks.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

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

**Version**: 12

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1608]

## Triage and analysis.

## Investigating Volume Shadow Copy Deleted or Resized via VssAdmin

The Volume Shadow Copy Service (VSS) is a Windows feature that enables system administrators to take snapshots of volumes
that can later be restored or mounted to recover specific files or folders.

A typical step in the playbook of an attacker attempting to deploy ransomware is to delete Volume Shadow
Copies to ensure that victims have no alternative to paying the ransom, making any action that deletes shadow
copies worth monitoring.

This rule monitors the execution of Vssadmin.exe to either delete or resize shadow copies.

### Possible investigation steps

- Investigate the program execution chain (parent process tree).
- Check whether the account is authorized to perform this operation.
- Confirm whether the account owner is aware of the operation.
- In the case of a resize operation, check if the resize value is equal to suspicious values, like 401MB.
- Investigate other alerts related to the user/host in the last 48 hours.
- If unsigned files are found on the process tree:
  - Capture copies of the files.
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for occurrences in other hosts.
- Check if any files on the host machine have been encrypted.


## False positive analysis

- This rule may produce benign true positives (B-TPs). If this activity is expected and noisy in your
environment, consider adding exceptions — preferably with a combination of user and command line conditions.

## Related rules

- Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
- Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Priority should be given due to the advanced stage of this activity on the attack.
- If malware was found, isolate the involved hosts to prevent the infection of other hosts.
- Disable the involved accounts, or restrict their ability to log on remotely.
- If data was encrypted, deleted, or modified, activate your data recovery plan.
- Reset the password of the involved accounts.
- Perform data recovery locally or restore the backups from replicated copies (cloud, other servers, etc.).


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1857]

```js
process where event.type in ("start", "process_started")
  and (process.name : "vssadmin.exe" or process.pe.original_file_name == "VSSADMIN.EXE") and
  process.args in ("delete", "resize") and process.args : "shadows*"
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



