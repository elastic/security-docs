---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-potential-credential-access-via-windows-utilities.html
---

# Potential Credential Access via Windows Utilities [prebuilt-rule-8-4-3-potential-credential-access-via-windows-utilities]

Identifies the execution of known Windows utilities often abused to dump LSASS memory or the Active Directory database (NTDS.dit) in preparation for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Investigation Guide
* Elastic Endgame

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3609]

## Triage and analysis

## Investigating Potential Credential Access via Windows Utilities

Local Security Authority Server Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens.

The `Ntds.dit` file is a database that stores Active Directory data, including information about user objects, groups, and group membership.

This rule looks for the execution of utilities that can extract credential data from the LSASS memory and Active Directory `Ntds.dit` file.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the command line to identify what information was targeted.
- Identify the target computer and its role in the IT environment.

## False positive analysis

- This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- If the host is a domain controller (DC):
  - Activate your incident response plan for total Active Directory compromise.
  - Review the privileges assigned to users that can access the DCs, to ensure that the least privilege principle is being followed and to reduce the attack surface.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4343]

```js
process where event.type == "start" and
(
  /* update here with any new lolbas with dump capability */
  (process.pe.original_file_name == "procdump" and process.args : "-ma") or
  (process.name : "ProcessDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \  (x86\))?\\Cisco Systems\\.*""") or
  (process.pe.original_file_name == "WriteMiniDump.exe" and not process.parent.executable regex~  """C:\\Program Files( \(x86\))?\\Steam\\.*""") or
  (process.pe.original_file_name == "RUNDLL32.EXE" and (process.args : "MiniDump*" or process.  command_line : "*comsvcs.dll*#24*")) or
  (process.pe.original_file_name == "RdrLeakDiag.exe" and process.args : "/fullmemdmp") or
  (process.pe.original_file_name == "SqlDumper.exe" and process.args : "0x01100*") or
  (process.pe.original_file_name == "TTTracer.exe" and process.args : "-dumpFull" and process.args  : "-attach") or
  (process.pe.original_file_name == "ntdsutil.exe" and process.args : "create*full*") or
  (process.pe.original_file_name == "diskshadow.exe" and process.args : "/s")
)
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

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)

* Sub-technique:

    * Name: NTDS
    * ID: T1003.003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/003/](https://attack.mitre.org/techniques/T1003/003/)



