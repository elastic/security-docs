---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-mimikatz-memssp-log-file-detected.html
---

# Mimikatz Memssp Log File Detected [prebuilt-rule-1-0-2-mimikatz-memssp-log-file-detected]

Identifies the password log file from the default Mimikatz memssp module.

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
* Credential Access

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1516]

## Triage and analysis.

## Investigating Mimikatz Memssp Log File Detected

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is an open-source tool used to collect, decrypt, and/or use cached
credentials. This tool is commonly abused by adversaries during the post-compromise stage where adversaries have gained
an initial foothold on an endpoint and are looking to elevate privileges and seek out additional authentication objects
such as tokens/hashes/credentials that can then be used to laterally move and pivot across a network.

This rule looks for the creation of a file named `mimilsa.log`, which is generated when using the Mimikatz misc::memssp
module, which injects a malicious Windows SSP to collect locally authenticated credentials, which includes the computer
account password, running service credentials, and any accounts that logon.

### Possible investigation steps

- Investigate script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Scope potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target
host.
- Retrieve and inspect the log file contents.
- By default, the log file is created in the same location as the DLL file.
- Search for DLL files created in the location, and retrieve any DLLs that are not signed:
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of these files.
    - Search for the existence of these files in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This file name `mimilsa.log` should not legitimately be created.

## Related rules

- Mimikatz Powershell Module Activity - ac96ceb8-4399-4191-af1d-4feeac1f1f46

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the host is a Domain Controller (DC):
  - Activate your incident response plan for total Active Directory compromise.
  - Review the permissions of users that can access the DCs.
- Reset passwords for all compromised accounts.
- Disable remote login for compromised user accounts.
- Reboot the host to remove the injected SSP from memory.
- Reimage the host operating system or restore compromised files to clean versions.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1752]

```js
file where file.name : "mimilsa.log" and process.name : "lsass.exe"
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



