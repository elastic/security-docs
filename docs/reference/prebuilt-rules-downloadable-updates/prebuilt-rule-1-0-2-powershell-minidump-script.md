---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-minidump-script.html
---

# PowerShell MiniDump Script [prebuilt-rule-1-0-2-powershell-minidump-script]

This rule detects PowerShell scripts capable of dumping process memory using WindowsErrorReporting or `Dbghelp.dll` MiniDumpWriteDump. Attackers can use this tooling to dump Local Security Authority Server Service (LSASS) memory and get access to credentials.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
* [https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-ProcessMiniDump.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-ProcessMiniDump.ps1)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1518]

## Triage and analysis.

## Investigating PowerShell MiniDump Script

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can abuse Process Memory Dump capabilities to extract credentials from LSASS or to obtain other
privileged information stored in the process memory.

### Possible investigation steps

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Check if the imported function was executed and which process it targeted.

## False positive analysis

- Regular users do not have a business justification for using scripting utilities to dump process memory, making false
positives unlikely.

## Related rules

- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe
- Potential Process Injection via PowerShell - 2e29e96a-b67c-455a-afe4-de6183431d0d

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.
- Reset the password for the user account.

## Config

The 'PowerShell Script Block Logging' logging policy must be enabled.
Steps to implement the logging policy with with Advanced Audit Configuration:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

Steps to implement the logging policy via registry:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```

## Rule query [_rule_query_1755]

```js
event.category:process and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM)
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



