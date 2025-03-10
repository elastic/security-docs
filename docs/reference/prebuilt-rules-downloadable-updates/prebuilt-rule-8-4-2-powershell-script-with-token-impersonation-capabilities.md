---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-powershell-script-with-token-impersonation-capabilities.html
---

# PowerShell Script with Token Impersonation Capabilities [prebuilt-rule-8-4-2-powershell-script-with-token-impersonation-capabilities]

Detects scripts that contain PowerShell functions, structures, or Windows API functions related to token impersonation/theft. Attackers may duplicate then impersonate another user’s token to escalate privileges and bypass access controls.

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

* [https://github.com/decoder-it/psgetsystem](https://github.com/decoder-it/psgetsystem)
* [https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/Get-System.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/Get-System.ps1)
* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation
* PowerShell

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3554]



## Rule query [_rule_query_4248]

```js
event.category:process and
  powershell.file.script_block_text:(
    "Invoke-TokenManipulation" or
    "ImpersonateNamedPipeClient" or
    "NtImpersonateThread" or
    (
      "STARTUPINFOEX" and
      "UpdateProcThreadAttribute"
    ) or
    (
      "AdjustTokenPrivileges" and
      "SeDebugPrivilege"
    ) or
    (
      ("DuplicateToken" or
      "DuplicateTokenEx") and
      ("SetThreadToken" or
      "ImpersonateLoggedOnUser" or
      "CreateProcessWithTokenW" or
      "CreatePRocessAsUserW" or
      "CreateProcessAsUserA")
    )
  ) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Token Impersonation/Theft
    * ID: T1134.001
    * Reference URL: [https://attack.mitre.org/techniques/T1134/001/](https://attack.mitre.org/techniques/T1134/001/)

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

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



