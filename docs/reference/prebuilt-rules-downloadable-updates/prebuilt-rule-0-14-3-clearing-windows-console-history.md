---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-clearing-windows-console-history.html
---

# Clearing Windows Console History [prebuilt-rule-0-14-3-clearing-windows-console-history]

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

* [https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/](https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/)
* [https://www.shellhacks.com/clear-history-powershell/](https://www.shellhacks.com/clear-history-powershell/)
* [https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 1

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Rule query [_rule_query_1508]

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



