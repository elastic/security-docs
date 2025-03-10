---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-conhost-spawned-by-suspicious-parent-process.html
---

# Conhost Spawned By Suspicious Parent Process [prebuilt-rule-8-3-1-conhost-spawned-by-suspicious-parent-process]

Detects when the Console Window Host (conhost.exe) process is spawned by a suspicious parent process, which could be indicative of code injection.

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

* [https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.html](https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2319]

## Triage and analysis

## Investigating Conhost Spawned By Suspicious Parent Process

The Windows Console Host, or `conhost.exe`, is both the server application for all of the Windows Console APIs as well as
the classic Windows user interface for working with command-line applications.

Attackers often rely on custom shell implementations to avoid using built-in command interpreters like `cmd.exe` and
`PowerShell.exe` and bypass application allowlisting and security features. Attackers commonly inject these implementations into
legitimate system processes.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file
modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Inspect the host for suspicious or abnormal behaviors in the alert timeframe.
- Retrieve the parent process executable and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell `Get-FileHash` cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- Suspicious Process from Conhost - 28896382-7d4f-4d50-9b72-67091901fd26
- Suspicious PowerShell Engine ImageLoad - 852c1f19-68e8-43a6-9dce-340771fe1be3

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2675]

```js
process where event.type in ("start", "process_started") and
  process.name : "conhost.exe" and
  process.parent.name : ("lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "explorer.exe", "dllhost.exe", "rundll32.exe",
                         "regsvr32.exe", "userinit.exe", "wininit.exe", "spoolsv.exe", "ctfmon.exe") and
  not (process.parent.name : "rundll32.exe" and
       process.parent.args : ("?:\\Windows\\Installer\\MSI*.tmp,zzzzInvokeManagedCustomActionOutOfProc",
                              "?:\\WINDOWS\\system32\\PcaSvc.dll,PcaPatchSdbTask",
                              "?:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie"))
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



