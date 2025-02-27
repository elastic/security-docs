---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-remote-execution-capabilities-via-winrm.html
---

# PowerShell Script with Remote Execution Capabilities via WinRM [powershell-script-with-remote-execution-capabilities-via-winrm]

Identifies the use of Cmdlets and methods related to remote execution activities using WinRM. Attackers can abuse WinRM to perform lateral movement using built-in tools.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)
* [https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/LateralMovement/PowerShellRemoting.cs](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/LateralMovement/PowerShellRemoting.cs)
* [https://github.com/BC-SECURITY/Empire/blob/main/empire/server/modules/powershell/lateral_movement/invoke_psremoting.py](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/modules/powershell/lateral_movement/invoke_psremoting.py)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Execution
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_522]

**Setup**

The *PowerShell Script Block Logging* logging policy must be enabled. Steps to implement the logging policy with Advanced Audit Configuration:

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


## Rule query [_rule_query_857]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    ("Invoke-WmiMethod" or "Invoke-Command" or "Enter-PSSession") and "ComputerName"
  ) and
  not user.id : "S-1-5-18" and
  not file.directory : (
    "C:\\Program Files\\LogicMonitor\\Agent\\tmp" or
    "C:\\Program Files\\WindowsPowerShell\\Modules\\icinga-powershell-framework\\cache" or
    "C:\\Program Files\\WindowsPowerShell\\Modules\\SmartCardTools\\1.2.2"
  ) and not
  powershell.file.script_block_text : (
    "Export-ModuleMember -Function @('Invoke-Expression''Invoke-Command')" and
    "function Invoke-Command {"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Windows Remote Management
    * ID: T1021.006
    * Reference URL: [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)

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



