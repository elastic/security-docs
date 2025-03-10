---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-disable-windows-event-and-security-logs-using-built-in-tools.html
---

# Disable Windows Event and Security Logs Using Built-in Tools [prebuilt-rule-0-14-2-disable-windows-event-and-security-logs-using-built-in-tools]

Identifies attempts to disable EventLog via the logman Windows utility, PowerShell, or auditpol. This is often done by attackers in an attempt to evade detection on a system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/logman](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/logman)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic
* Ivan Ninichuck
* Austin Songer

**Rule license**: Elastic License v2

## Rule query [_rule_query_1430]

```js
process where event.type in ("start", "process_started") and

  ((process.name:"logman.exe" or process.pe.original_file_name == "Logman.exe") and
      process.args : "EventLog-*" and process.args : ("stop", "delete")) or

  ((process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or process.pe.original_file_name in
      ("pwsh.exe", "powershell.exe", "powershell_ise.exe")) and
	process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled")  or

  ((process.name:"auditpol.exe" or process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable")
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

    * Name: Clear Windows Event Logs
    * ID: T1070.001
    * Reference URL: [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)



