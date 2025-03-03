---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-archive-compression-capabilities.html
---

# PowerShell Script with Archive Compression Capabilities [powershell-script-with-archive-compression-capabilities]

Identifies the use of Cmdlets and methods related to archive compression activities. Adversaries will often compress and encrypt data in preparation for exfiltration.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_518]

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


## Rule query [_rule_query_852]

```js
event.category:process and host.os.type:windows and
(
  powershell.file.script_block_text : (
    "IO.Compression.ZipFile" or
    "IO.Compression.ZipArchive" or
    "ZipFile.CreateFromDirectory" or
    "IO.Compression.BrotliStream" or
    "IO.Compression.DeflateStream" or
    "IO.Compression.GZipStream" or
    "IO.Compression.ZLibStream"
  ) and
  powershell.file.script_block_text : (
    "CompressionLevel" or
    "CompressionMode" or
    "ZipArchiveMode"
  ) or
  powershell.file.script_block_text : "Compress-Archive"
) and
not powershell.file.script_block_text : (
  "Compress-Archive -Path 'C:\ProgramData\Lenovo\Udc\diagnostics\latest" or
  ("Copyright: (c) 2017, Ansible Project" and "Ansible.ModuleUtils.Backup")
) and
not file.directory : (
  "C:\Program Files\Microsoft Dependency Agent\plugins\lib" or
  "C:\Program Files\WindowsPowerShell\Modules\icinga-powershell-framework\cache" or
  "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

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



