---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-suspicious-discovery-related-windows-api-functions.html
---

# PowerShell Suspicious Discovery Related Windows API Functions [powershell-suspicious-discovery-related-windows-api-functions]

This rule detects the use of discovery-related Windows API functions in PowerShell Scripts. Attackers can use these functions to perform various situational awareness related activities, like enumerating users, shares, sessions, domain trusts, groups, etc.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/BC-SECURITY/Empire/blob/9259e5106986847d2bb770c4289c0c0f1adf2344/data/module_source/situational_awareness/network/powerview.ps1#L21413](https://github.com/BC-SECURITY/Empire/blob/9259e5106986847d2bb770c4289c0c0f1adf2344/data/module_source/situational_awareness/network/powerview.ps1#L21413)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Collection
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: PowerShell Logs

**Version**: 316

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_809]

**Triage and analysis**

**Investigating PowerShell Suspicious Discovery Related Windows API Functions**

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell to interact with the Win32 API to bypass command line based detections, using libraries like PSReflect or Get-ProcAddress Cmdlet.

**Possible investigation steps**

* Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Examine file or network events from the involved PowerShell process for suspicious behavior.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Evaluate whether the user needs to use PowerShell to complete tasks.
* Check for additional PowerShell and command-line logs that indicate that imported functions were run.

**False positive analysis**

* Discovery activities themselves are not inherently malicious if occurring in isolation, as long as the script does not contain other capabilities, and there are no other alerts related to the user or host; such alerts can be dismissed. However, analysts should keep in mind that this is not a common way of getting information, making it suspicious.

**Related rules**

* PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_528]

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


## Rule query [_rule_query_863]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    NetShareEnum or
    NetWkstaUserEnum or
    NetSessionEnum or
    NetLocalGroupEnum or
    NetLocalGroupGetMembers or
    DsGetSiteName or
    DsEnumerateDomainTrusts or
    WTSEnumerateSessionsEx or
    WTSQuerySessionInformation or
    LsaGetLogonSessionData or
    QueryServiceObjectSecurity or
    GetComputerNameEx or
    NetWkstaGetInfo or
    GetUserNameEx or
    NetUserEnum or
    NetUserGetInfo or
    NetGroupEnum or
    NetGroupGetInfo or
    NetGroupGetUsers or
    NetWkstaTransportEnum or
    NetServerGetInfo or
    LsaEnumerateTrustedDomains  or
    NetScheduleJobEnum or
    NetUserModalsGet
  ) and
  not powershell.file.script_block_text : (
    ("DsGetSiteName" and ("DiscoverWindowsComputerProperties.ps1" and "param($SourceType, $SourceId, $ManagedEntityId, $ComputerIdentity)")) or
    ("# Copyright: (c) 2018, Ansible Project" and "#Requires -Module Ansible.ModuleUtils.AddType" and "#AnsibleRequires -CSharpUtil Ansible.Basic") or
    ("Ansible.Windows.Setup" and "Ansible.Windows.Setup" and "NativeMethods.NetWkstaGetInfo(null, 100, out netBuffer);")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)

* Technique:

    * Name: Domain Trust Discovery
    * ID: T1482
    * Reference URL: [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)

* Technique:

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

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

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Network Shared Drive
    * ID: T1039
    * Reference URL: [https://attack.mitre.org/techniques/T1039/](https://attack.mitre.org/techniques/T1039/)



