---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-powershell-keylogging-script.html
---

# PowerShell Keylogging Script [prebuilt-rule-0-14-3-powershell-keylogging-script]

Detects the use of Win32 API Functions that can be used to capture user Keystrokes in PowerShell Scripts. Attackers use this technique to capture user input, looking for credentials and/or other valuable data.

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

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1502]

```js
event.category:process and
  (
   powershell.file.script_block_text : (GetAsyncKeyState or NtUserGetAsyncKeyState or GetKeyboardState or Get-Keystrokes) or
   powershell.file.script_block_text : ((SetWindowsHookA or SetWindowsHookW or SetWindowsHookEx or SetWindowsHookExA or NtUserSetWindowsHookEx) and (GetForegroundWindow or GetWindowTextA or GetWindowTextW or WM_KEYBOARD_LL))
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



