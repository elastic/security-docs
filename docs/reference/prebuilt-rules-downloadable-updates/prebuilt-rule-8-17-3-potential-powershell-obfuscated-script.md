---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-powershell-obfuscated-script.html
---

# Potential PowerShell Obfuscated Script [prebuilt-rule-8-17-3-potential-powershell-obfuscated-script]

Identifies scripts that contain patterns and known methods that obfuscate PowerShell code. Attackers can use obfuscation techniques to bypass PowerShell security protections such as Antimalware Scan Interface (AMSI).

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: PowerShell Logs

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_905]

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


## Rule query [_rule_query_4957]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "[string]::join" or
    "-Join" or
    "[convert]::toint16" or
    "[char][int]$_" or
    ("ConvertTo-SecureString" and "PtrToStringAuto") or
    ".GetNetworkCredential().password" or
    "-BXor" or
    ("replace" and "char") or
    "[array]::reverse" or
    "-replace"
  ) and
  powershell.file.script_block_text : (
    ("$pSHoMe[" and "+$pSHoMe[") or
    ("$ShellId[" and "+$ShellId[") or
    ("$env:ComSpec[4" and "25]-Join") or
    (("Set-Variable" or "SV" or "Set-Item") and "OFS") or
    ("*MDR*" and "Name[3,11,2]") or
    ("$VerbosePreference" and "[1,3]+'X'-Join''") or
    ("rahc" or "ekovin" or "gnirts" or "ecnereferpesobrev" or "ecalper" or "cepsmoc" or "dillehs") or
    ("System.Management.Automation.$([cHAr]" or "System.$([cHAr]" or ")+[cHAR]([byte]")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

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



