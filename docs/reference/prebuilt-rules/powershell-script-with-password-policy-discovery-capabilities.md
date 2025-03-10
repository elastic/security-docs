---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-password-policy-discovery-capabilities.html
---

# PowerShell Script with Password Policy Discovery Capabilities [powershell-script-with-password-policy-discovery-capabilities]

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Execution
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_521]

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


## Rule query [_rule_query_856]

```js
event.category: "process" and host.os.type:windows and
(
  powershell.file.script_block_text: (
    "Get-ADDefaultDomainPasswordPolicy" or
    "Get-ADFineGrainedPasswordPolicy" or
    "Get-ADUserResultantPasswordPolicy" or
    "Get-DomainPolicy" or
    "Get-GPPPassword" or
    "Get-PassPol"
  )
  or
  powershell.file.script_block_text: (
    ("defaultNamingContext" or "ActiveDirectory.DirectoryContext" or "ActiveDirectory.DirectorySearcher") and
    (
      (
        ".MinLengthPassword" or
        ".MinPasswordAge" or
        ".MaxPasswordAge"
      ) or
      (
        "minPwdAge" or
        "maxPwdAge" or
        "minPwdLength"
      ) or
      (
        "msDS-PasswordSettings"
      )
    )
  )
) and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
  and not
  (
    powershell.file.script_block_text : ("43c15630-959c-49e4-a977-758c5cc93408" and "CmdletsToExport" and "ActiveDirectory.Types.ps1xml")
  )
  and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Password Policy Discovery
    * ID: T1201
    * Reference URL: [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)

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



