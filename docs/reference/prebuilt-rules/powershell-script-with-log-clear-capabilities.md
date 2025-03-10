---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-log-clear-capabilities.html
---

# PowerShell Script with Log Clear Capabilities [powershell-script-with-log-clear-capabilities]

Identifies the use of Cmdlets and methods related to Windows event log deletion activities. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.

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

* [https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.clear](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.clear)
* [https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.clearlog](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.clearlog)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_520]

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


## Rule query [_rule_query_855]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "Clear-EventLog" or
    "Remove-EventLog" or
    ("Eventing.Reader.EventLogSession" and ".ClearLog") or
    ("Diagnostics.EventLog" and ".Clear")
  ) and
  not powershell.file.script_block_text : (
    "CmdletsToExport=@(\"Add-Content\""
  ) and
  not file.directory : "C:\Program Files\WindowsAdminCenter\PowerShellModules\Microsoft.WindowsAdminCenter.Configuration"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Windows Event Logs
    * ID: T1070.001
    * Reference URL: [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)

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



