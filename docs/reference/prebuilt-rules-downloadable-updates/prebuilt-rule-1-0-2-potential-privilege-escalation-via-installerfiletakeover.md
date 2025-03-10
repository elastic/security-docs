---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-privilege-escalation-via-installerfiletakeover.html
---

# Potential Privilege Escalation via InstallerFileTakeOver [prebuilt-rule-1-0-2-potential-privilege-escalation-via-installerfiletakeover]

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1661]

## Triage and analysis

## Investigating Potential Privilege Escalation via InstallerFileTakeOver

InstallerFileTakeOver is a weaponized escalation of privilege proof of concept (EoP PoC) to the CVE-2021-41379 vulnerability. Upon successful exploitation, an
unprivileged user will escalate privileges to SYSTEM/NT AUTHORITY.

This rule detects the default execution of the PoC, which overwrites the `elevation_service.exe` DACL and copies itself
to the location to escalate privileges. An attacker is able to still take over any file that is not in use (locked),
which is outside the scope of this rule.

### Possible investigation steps:

- Check the executable's digital signature.
- Look for additional processes spawned by the process, command lines, and network communications.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check for similar behavior in other hosts on the environment.
- Retrieve the file and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- Verify whether a digital signature exists in the executable, and if it is valid.

## Related rules

- Suspicious DLL Loaded for Persistence or Privilege Escalation - bfeaf89b-a2a7-48a3-817f-e41829dc61ee

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the identified indicators of compromise (IoCs).
- Remove and block malicious artifacts identified on the triage.
- Disable user account’s ability to log in remotely.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Determine the initial infection vector.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1924]

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



