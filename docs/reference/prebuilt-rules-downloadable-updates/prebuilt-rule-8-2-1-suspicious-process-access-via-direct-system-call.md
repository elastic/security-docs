---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-suspicious-process-access-via-direct-system-call.html
---

# Suspicious Process Access via Direct System Call [prebuilt-rule-8-2-1-suspicious-process-access-via-direct-system-call]

Identifies suspicious process access events from an unknown memory region. Endpoint security solutions usually hook userland Windows APIs in order to decide if the code that is being executed is malicious or not. It’s possible to bypass hooked functions by writing malicious functions that call syscalls directly.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/SBousseaden/status/1278013896440324096](https://twitter.com/SBousseaden/status/1278013896440324096)
* [https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2140]

## Triage and analysis

## Investigating Suspicious Process Access via Direct System Call

Endpoint security solutions usually hook userland Windows APIs in order to decide if the code that is being executed is
malicious or not. It's possible to bypass hooked functions by writing malicious functions that call syscalls directly.

More context and technical details can be found in this [research blog](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/).

This rule identifies suspicious process access events from an unknown memory region. Attackers can use direct system
calls to bypass security solutions that rely on hooks.

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
  - Use the PowerShell `Get-FileHash` cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This detection may be triggered by certain applications that install root certificates for the purpose of inspecting
SSL traffic. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove the malicious certificate from the root certificate store.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2430]

```js
process where event.code == "10" and
 length(winlog.event_data.CallTrace) > 0 and

 /* Sysmon CallTrace starting with unknown memory module instead of ntdll which host Windows NT Syscalls */
 not winlog.event_data.CallTrace :
            ("?:\\WINDOWS\\SYSTEM32\\ntdll.dll*",
             "?:\\WINDOWS\\SysWOW64\\ntdll.dll*",
             "?:\\Windows\\System32\\wow64cpu.dll*",
             "?:\\WINDOWS\\System32\\wow64win.dll*",
             "?:\\Windows\\System32\\win32u.dll*") and

 not winlog.event_data.TargetImage :
            ("?:\\Program Files (x86)\\Malwarebytes Anti-Exploit\\mbae-svc.exe",
             "?:\\Program Files\\Cisco\\AMP\\*\\sfc.exe",
             "?:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\msedgewebview2.exe",
             "?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\*\\AcroCEF.exe") and

 not (process.executable : ("?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                            "?:\\Program Files (x86)\\World of Warcraft\\_classic_\\WowClassic.exe") and
      not winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



