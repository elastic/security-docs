---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-suspicious-discovery-related-windows-api-functions.html
---

# PowerShell Suspicious Discovery Related Windows API Functions [prebuilt-rule-1-0-2-powershell-suspicious-discovery-related-windows-api-functions]

This rule detects the use of discovery-related Windows API functions in PowerShell scripts. Attackers can use these functions to perform various situational awareness-related activities, like enumerating users, shares, sessions, domain trusts, groups, etc.

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

* [https://github.com/BC-SECURITY/Empire/blob/9259e5106986847d2bb770c4289c0c0f1adf2344/data/module_source/situational_awareness/network/powerview.ps1#L21413](https://github.com/BC-SECURITY/Empire/blob/9259e5106986847d2bb770c4289c0c0f1adf2344/data/module_source/situational_awareness/network/powerview.ps1#L21413)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1578]

## Triage and analysis.

## Investigating PowerShell Suspicious Discovery Related Windows API Functions

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell to interact with the Win32 API to bypass command line based detections, using libraries
like PSReflect or Get-ProcAddress Cmdlet.

### Possible investigation steps

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Check if the imported function was executed.

## False positive analysis

- Discovery activities themselves are not inherently malicious if occurring in isolation, as long as the script does not
contain other capabilities, and there are no other alerts related to the user or host; such alerts can be dismissed.
However, analysts should keep in mind that this is not a common way of getting information, making it suspicious.

## Related rules

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

## Rule query [_rule_query_1825]

```js
event.category:process and
  powershell.file.script_block_text : (
    NetShareEnum or
    NetWkstaUserEnum or
    NetSessionEnum or
    NetLocalGroupEnum or
    NetLocalGroupGetMembers or
    DsGetSiteName or
    DsEnumerateDomainTrusts or
    WTSEnumerateSessionsEx or
    WTSQuerySessionInformation or
    LsaGetLogonSessionData or
    QueryServiceObjectSecurity
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)

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

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



