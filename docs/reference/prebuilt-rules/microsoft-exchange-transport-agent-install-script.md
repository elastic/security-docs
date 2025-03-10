---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-exchange-transport-agent-install-script.html
---

# Microsoft Exchange Transport Agent Install Script [microsoft-exchange-transport-agent-install-script]

Identifies the use of Cmdlets and methods related to Microsoft Exchange Transport Agents install. Adversaries may leverage malicious Microsoft Exchange Transport Agents to execute tasks in response to adversary-defined criteria, establishing persistence.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_350]

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


## Rule query [_rule_query_571]

```js
event.category: "process" and host.os.type:windows and
  powershell.file.script_block_text : (
    (
    "Install-TransportAgent" or
    "Enable-TransportAgent"
    )
  ) and
  not user.id : "S-1-5-18" and
  not powershell.file.script_block_text : (
    "'Install-TransportAgent', 'Invoke-MonitoringProbe', 'Mount-Database', 'Move-ActiveMailboxDatabase'," or
    "'Enable-TransportAgent', 'Enable-TransportRule', 'Export-ActiveSyncLog', 'Export-AutoDiscoverConfig'," or
    ("scriptCmd.GetSteppablePipeline" and "ForwardHelpTargetName Install-TransportAgent")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Transport Agent
    * ID: T1505.002
    * Reference URL: [https://attack.mitre.org/techniques/T1505/002/](https://attack.mitre.org/techniques/T1505/002/)

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



