---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-bypass-uac-via-event-viewer.html
---

# Bypass UAC via Event Viewer [prebuilt-rule-8-3-1-bypass-uac-via-event-viewer]

Identifies User Account Control (UAC) bypass via eventvwr.exe. Attackers bypass UAC to stealthily execute code with elevated permissions.

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
* Privilege Escalation

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2330]

## Triage and analysis

## Investigating Bypass UAC via Event Viewer

Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as low to high integrity levels)
to perform a task under administrator-level permissions, possibly by prompting the user for confirmation.
UAC can deny an operation under high-integrity enforcement, or allow the user to perform the action if they are in the
local administrators group and enter an administrator password when prompted.

For more information about the UAC and how it works, check the [official Microsoft docs page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works).

During startup, `eventvwr.exe` checks the registry value of the `HKCU\Software\Classes\mscfile\shell\open\command`
registry key for the location of `mmc.exe`, which is used to open the `eventvwr.msc` saved console file. If the location
of another binary or script is added to this registry value, it will be executed as a high-integrity process without a
UAC prompt being displayed to the user. This rule detects this UAC bypass by monitoring processes spawned by
`eventvwr.exe` other than `mmc.exe` and `werfault.exe`.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Inspect the host for suspicious or abnormal behaviors in the alert timeframe.
- Investigate abnormal behaviors observed by the subject process such as network connections, registry or file
modifications, and any spawned child processes.
- Retrieve the process executable and determine if it is malicious:
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

## Rule query [_rule_query_2695]

```js
process where event.type in ("start", "process_started") and
  process.parent.name : "eventvwr.exe" and
  not process.executable :
            ("?:\\Windows\\SysWOW64\\mmc.exe",
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\SysWOW64\\WerFault.exe",
             "?:\\Windows\\System32\\WerFault.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)



