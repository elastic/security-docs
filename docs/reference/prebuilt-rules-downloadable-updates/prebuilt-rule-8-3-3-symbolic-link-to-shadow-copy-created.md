---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-symbolic-link-to-shadow-copy-created.html
---

# Symbolic Link to Shadow Copy Created [prebuilt-rule-8-3-3-symbolic-link-to-shadow-copy-created]

Identifies the creation of symbolic links to a shadow copy. Symbolic links can be used to access files in the shadow copy, including sensitive files such as ntds.dit, System Boot Key and browser offline credentials.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mklink](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mklink)
* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
* [https://blog.netwrix.com/2021/11/30/extracting-password-hashes-from-the-ntds-dit-file/](https://blog.netwrix.com/2021/11/30/extracting-password-hashes-from-the-ntds-dit-file/)
* [https://www.hackingarticles.in/credential-dumping-ntds-dit/](https://www.hackingarticles.in/credential-dumping-ntds-dit/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3037]

## Triage and analysis

## Investigating Symbolic Link to Shadow Copy Created

Shadow copies are backups or snapshots of an endpoint's files or volumes while they are in use. Adversaries may attempt to discover and create symbolic links to these shadow copies in order to copy sensitive information offline. If Active Directory (AD) is in use, often the ntds.dit file is a target as it contains password hashes, but an offline copy is needed to extract these hashes and potentially conduct lateral movement.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Determine if a volume shadow copy was recently created on this endpoint.
- Review privileges of the end user as this requires administrative access.
- Verify if the ntds.dit file was successfully copied and determine its copy destination.
- Investigate for registry SYSTEM file copies made recently or saved via Reg.exe.
- Investigate recent deletions of volume shadow copies.
- Identify other files potentially copied from volume shadow copy paths directly.

## False positive analysis

- This rule should cause very few false positives. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- NTDS or SAM Database File Copied - 3bc6deaa-fbd4-433a-ae21-3e892f95624f

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- If the entire domain or the `krbtgt` user was compromised:
  - Activate your incident response plan for total Active Directory compromise which should include, but not be limited to, a password reset (twice) of the `krbtgt` user.
- Locate and remove static files copied from volume shadow copies.
- Command-Line tool mklink should require administrative access by default unless in developer mode.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

Ensure advanced audit policies for Windows are enabled, specifically:
Object Access policies [Event ID 4656](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4656) (Handle to an Object was Requested)

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
System Audit Policies >
Object Access >
Audit File System (Success,Failure)
Audit Handle Manipulation (Success,Failure)
```

This event will only trigger if symbolic links are created from a new process spawning cmd.exe or powershell.exe with the correct arguments.
Direct access to a shell and calling symbolic link creation tools will not generate an event matching this rule.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_3534]

```js
process where event.type in ("start","process_created") and
 process.pe.original_file_name in ("Cmd.Exe","PowerShell.EXE") and

 /* Create Symbolic Link to Shadow Copies */
 process.args : ("*mklink*", "*SymbolicLink*") and process.command_line : ("*HarddiskVolumeShadowCopy*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)



