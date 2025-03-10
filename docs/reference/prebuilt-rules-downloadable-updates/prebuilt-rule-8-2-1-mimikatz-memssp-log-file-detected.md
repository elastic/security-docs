---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-mimikatz-memssp-log-file-detected.html
---

# Mimikatz Memssp Log File Detected [prebuilt-rule-8-2-1-mimikatz-memssp-log-file-detected]

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

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2078]

## Triage and analysis

## Investigating Mimikatz Memssp Log File Detected

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is an open-source tool used to collect, decrypt, and/or use cached
credentials. This tool is commonly abused by adversaries during the post-compromise stage where adversaries have gained
an initial foothold on an endpoint and are looking to elevate privileges and seek out additional authentication objects
such as tokens/hashes/credentials that can then be used to laterally move and pivot across a network.

This rule looks for the creation of a file named `mimilsa.log`, which is generated when using the Mimikatz misc::memssp
module, which injects a malicious Windows SSP to collect locally authenticated credentials, which includes the computer
account password, running service credentials, and any accounts that logon.

### Possible investigation steps

- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target
host.
- Retrieve and inspect the log file contents.
- Search for DLL files created in the same location as the log file, and retrieve unsigned DLLs.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of these files.
    - Search for the existence of these files in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
  - Identify the process that created the DLL using file creation events.

## False positive analysis

- This file name `mimilsa.log` should not legitimately be created.

## Related rules

- Mimikatz Powershell Module Activity - ac96ceb8-4399-4191-af1d-4feeac1f1f46

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the host is a Domain Controller (DC):
  - Activate your incident response plan for total Active Directory compromise.
  - Review the privileges assigned to users that can access the DCs to ensure that the least privilege principle is
  being followed and reduce the attack surface.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Reboot the host to remove the injected SSP from memory.
- Reimage the host operating system or restore compromised files to clean versions.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2368]

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



