---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-privilege-escalation-via-installerfiletakeover.html
---

# Potential Privilege Escalation via InstallerFileTakeOver [prebuilt-rule-8-4-1-potential-privilege-escalation-via-installerfiletakeover]

Identifies a potential exploitation of InstallerTakeOver (CVE-2021-41379) default PoC execution. Successful exploitation allows an unprivileged user to escalate privileges to SYSTEM.

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

**References**:

* [https://github.com/klinix5/InstallerFileTakeOver](https://github.com/klinix5/InstallerFileTakeOver)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2847]

## Triage and analysis

## Investigating Potential Privilege Escalation via InstallerFileTakeOver

InstallerFileTakeOver is a weaponized escalation of privilege proof of concept (EoP PoC) to the CVE-2021-41379 vulnerability. Upon successful exploitation, an
unprivileged user will escalate privileges to SYSTEM/NT AUTHORITY.

This rule detects the default execution of the PoC, which overwrites the `elevation_service.exe` DACL and copies itself
to the location to escalate privileges. An attacker is able to still take over any file that is not in use (locked),
which is outside the scope of this rule.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Look for additional processes spawned by the process, command lines, and network communications.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze the file using a private sandboxed analysis system.
  - Observe and collect information about the following activities in both the sandbox and the alert subject host:
    - Attempts to contact external domains and addresses.
      - Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by
      filtering by the process' `process.entity_id`.
      - Examine the DNS cache for suspicious or anomalous entries.
        - !{osquery{"query":"SELECT * FROM dns_cache", "label":"Osquery - Retrieve DNS Cache"}}
    - Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related
    processes in the process tree.
    - Examine the host services for suspicious or anomalous entries.
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services","label":"Osquery - Retrieve All Services"}}
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE "%LocalSystem" OR user_account LIKE "%LocalService" OR user_account LIKE "%NetworkService" OR user_account == null)","label":"Osquery - Retrieve Services Running on User Accounts"}}
      - !{osquery{"query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != "trusted"","label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link"}}
  - Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and
  reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- Verify whether a digital signature exists in the executable, and if it is valid.

## Related rules

- Suspicious DLL Loaded for Persistence or Privilege Escalation - bfeaf89b-a2a7-48a3-817f-e41829dc61ee

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3251]

```js
/* This rule is compatible with both Sysmon and Elastic Endpoint */

process where event.type == "start" and
    (?process.Ext.token.integrity_level_name : "System" or
    ?winlog.event_data.IntegrityLevel : "System") and
    (
      (process.name : "elevation_service.exe" and
       not process.pe.original_file_name == "elevation_service.exe") or

      (process.parent.name : "elevation_service.exe" and
       process.name : ("rundll32.exe", "cmd.exe", "powershell.exe"))
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



