---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-powershell-suspicious-script-with-clipboard-retrieval-capabilities.html
---

# PowerShell Suspicious Script with Clipboard Retrieval Capabilities [prebuilt-rule-8-7-1-powershell-suspicious-script-with-clipboard-retrieval-capabilities]

Detects PowerShell scripts that can get the contents of the clipboard, which attackers can abuse to retrieve sensitive information like credentials, messages, etc.

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

* [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-clipboard](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-clipboard)
* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-ClipboardContents.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-ClipboardContents.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection
* PowerShell

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4652]

```js
event.category:process and
  (powershell.file.script_block_text : (
    "Windows.Clipboard" or
    "Windows.Forms.Clipboard" or
    "Windows.Forms.TextBox"
   ) and
   powershell.file.script_block_text : (
    "]::GetText" or
    ".Paste()"
  )) or powershell.file.script_block_text : "Get-Clipboard"
  and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Clipboard Data
    * ID: T1115
    * Reference URL: [https://attack.mitre.org/techniques/T1115/](https://attack.mitre.org/techniques/T1115/)

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



