---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-volume-shadow-copy-deletion-via-wmic.html
---

# Volume Shadow Copy Deletion via WMIC [prebuilt-rule-8-3-2-volume-shadow-copy-deletion-via-wmic]

Identifies use of wmic.exe for shadow copy deletion on endpoints. This commonly occurs in tandem with ransomware or other destructive attacks.

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
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2515]

## Triage and analysis

## Investigating Volume Shadow Copy Deletion via WMIC

The Volume Shadow Copy Service (VSS) is a Windows feature that enables system administrators to take snapshots of volumes
that can later be restored or mounted to recover specific files or folders.

A typical step in the playbook of an attacker attempting to deploy ransomware is to delete Volume Shadow
Copies to ensure that victims have no alternative to paying the ransom, making any action that deletes shadow
copies worth monitoring.

This rule monitors the execution of `wmic.exe` to interact with VSS via the `shadowcopy` alias and delete parameter.

### Possible investigation steps

- Investigate the program execution chain (parent process tree).
- Check whether the account is authorized to perform this operation.
- Contact the account owner and confirm whether they are aware of this activity.
- In the case of a resize operation, check if the resize value is equal to suspicious values, like 401MB.
- Investigate other alerts associated with the user/host during the past 48 hours.
- If unsigned files are found on the process tree, retrieve them and determine if they are malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for occurrences in other hosts.
- Check if any files on the host machine have been encrypted.


## False positive analysis

- This rule has chances of producing benign true positives (B-TPs). If this activity is expected and noisy in your
environment, consider adding exceptions — preferably with a combination of user and command line conditions.

## Related rules

- Volume Shadow Copy Deleted or Resized via VssAdmin - b5ea4bfe-a1b2-421f-9d47-22a75a6f2921
- Volume Shadow Copy Deletion via PowerShell - d99a037b-c8e2-47a5-97b9-170d076827c4

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Priority should be given due to the advanced stage of this activity on the attack.
- Consider isolating the involved host to prevent destructive behavior, which is commonly associated with this activity.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- If data was encrypted, deleted, or modified, activate your data recovery plan.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Perform data recovery locally or restore the backups from replicated copies (cloud, other servers, etc.).
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2888]

```js
process where event.type == "start" and
  (process.name : "WMIC.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
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



