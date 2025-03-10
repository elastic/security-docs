---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-svchost-spawning-cmd.html
---

# Svchost spawning Cmd [prebuilt-rule-8-2-1-svchost-spawning-cmd]

Identifies a suspicious parent child process relationship with cmd.exe descending from svchost.exe

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

**References**:

* [https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747](https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 14

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2163]

## Triage and analysis

## Investigating Svchost spawning Cmd

The Service Host process (SvcHost) is a system process that can host one, or multiple, Windows services in the Windows
NT family of operating systems. Note that `Svchost.exe` is reserved for use by the operating system and should not be
used by non-Windows services.

This rule looks for the creation of the `cmd.exe` process with `svchost.exe` as its parent process. This is an unusual
behavior that can indicate the masquerading of a malicious process as `svchost.exe` or exploitation for privilege
escalation.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate abnormal behaviors observed by the subject process such as network connections, registry or file
modifications, and any spawned child processes.
- Retrieve the process executable and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

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
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2453]

```js
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.name : "cmd.exe" and
  not (process.pe.original_file_name : "cmd.exe" and process.args : (
    "??:\\Program Files\\Npcap\\CheckStatus.bat?",
    "?:\\Program Files\\Npcap\\CheckStatus.bat",
    "\\system32\\cleanmgr.exe",
    "?:\\Windows\\system32\\silcollector.cmd",
    "\\system32\\AppHostRegistrationVerifier.exe",
    "\\system32\\ServerManagerLauncher.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



