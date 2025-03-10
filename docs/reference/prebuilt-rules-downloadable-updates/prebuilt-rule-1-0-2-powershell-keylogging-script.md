---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-keylogging-script.html
---

# PowerShell Keylogging Script [prebuilt-rule-1-0-2-powershell-keylogging-script]

Detects the use of Win32 API Functions that can be used to capture user keystrokes in PowerShell scripts. Attackers use this technique to capture user input and look for credentials and/or other valuable data.

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

* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-Keystrokes.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-Keystrokes.ps1)
* [https://github.com/MojtabaTajik/FunnyKeylogger/blob/master/FunnyLogger.ps1](https://github.com/MojtabaTajik/FunnyKeylogger/blob/master/FunnyLogger.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1493]

## Triage and analysis.

## Investigating PowerShell Keylogging Script

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can abuse PowerShell capabilities to capture user keystrokes with the goal of stealing credentials and other
valuable information as credit card data and confidential conversations.

### Possible investigation steps:

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Investigate if the script stores the captured data locally.
- Investigate if the script contains exfiltration capabilities and the destination of this exfiltration.
- Assess network data to determine if the host communicated with the exfiltration server.

## False positive analysis

- Regular users do not have a business justification for using scripting utilities to capture keystrokes, making
false positives unlikely. In the case of authorized benign true positives (B-TPs), exceptions can be added.

## Related rules

- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- The response must be prioritized if this alert involves key executives or potentially valuable targets for espionage.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.
- Reset the password for the user account and other potentially compromised accounts (email, services, CRMs, etc.).

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

## Rule query [_rule_query_1727]

```js
event.category:process and
  (
   powershell.file.script_block_text : (GetAsyncKeyState or NtUserGetAsyncKeyState or GetKeyboardState or "Get-Keystrokes") or
   powershell.file.script_block_text : (
        (SetWindowsHookA or SetWindowsHookW or SetWindowsHookEx or SetWindowsHookExA or NtUserSetWindowsHookEx) and
        (GetForegroundWindow or GetWindowTextA or GetWindowTextW or "WM_KEYBOARD_LL")
   )
   )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Input Capture
    * ID: T1056
    * Reference URL: [https://attack.mitre.org/techniques/T1056/](https://attack.mitre.org/techniques/T1056/)

* Sub-technique:

    * Name: Keylogging
    * ID: T1056.001
    * Reference URL: [https://attack.mitre.org/techniques/T1056/001/](https://attack.mitre.org/techniques/T1056/001/)

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



