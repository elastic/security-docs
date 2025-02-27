---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-portable-executable-encoded-in-powershell-script.html
---

# Suspicious Portable Executable Encoded in Powershell Script [prebuilt-rule-1-0-2-suspicious-portable-executable-encoded-in-powershell-script]

Detects the presence of a portable executable (PE) in a PowerShell script by looking for its encoded header. Attackers embed PEs into PowerShell scripts to inject them into memory, avoiding defences by not writing to disk.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1592]

## Triage and analysis.

## Investigating Suspicious Portable Executable Encoded in Powershell Script

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can abuse PowerShell in-memory capabilities to inject executables into memory without touching the disk,
bypassing file-based security protections. These executables are generally base64 encoded.

### Possible investigation steps

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Retrieve the script and execute it in a sandbox or controlled environment.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- PowerShell Reflection Assembly Load - e26f042e-c590-4e82-8e05-41e81bd822ad
- PowerShell Suspicious Payload Encoded and Compressed - 81fe9dc6-a2d7-4192-a2d8-eed98afc766a
- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host to prevent further post-compromise behavior.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.

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

## Rule query [_rule_query_1840]

```js
event.category:process and
  powershell.file.script_block_text : (
    TVqQAAMAAAAEAAAA
  )
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

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



