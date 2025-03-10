---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-clearing-windows-console-history.html
---

# Clearing Windows Console History [prebuilt-rule-8-3-2-clearing-windows-console-history]

Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://stefanos.cloud/kb/how-to-clear-the-powershell-command-history/](https://stefanos.cloud/kb/how-to-clear-the-powershell-command-history/)
* [https://www.shellhacks.com/clear-history-powershell/](https://www.shellhacks.com/clear-history-powershell/)
* [https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* has_guide

**Version**: 101

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2435]

## Triage and analysis

## Investigating Clearing Windows Console History

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can try to cover their tracks by clearing PowerShell console history. PowerShell has two different ways of
logging commands: the built-in history and the command history managed by the PSReadLine module. This rule looks for the
execution of commands that can clear the built-in PowerShell logs or delete the `ConsoleHost_history.txt` file.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
  - Verify if any other anti-forensics behaviors were observed.
- Investigate the PowerShell logs on the SIEM to determine if there was suspicious behavior that an attacker may be
trying to cover up.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).
  - Ensure that PowerShell auditing policies and log collection are in place to grant future visibility.

## Rule query [_rule_query_2802]

```js
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
     (process.args : "*Clear-History*" or
     (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
     (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal on Host
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Command History
    * ID: T1070.003
    * Reference URL: [https://attack.mitre.org/techniques/T1070/003/](https://attack.mitre.org/techniques/T1070/003/)



