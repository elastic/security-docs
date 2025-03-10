---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-process-injection-via-powershell.html
---

# Potential Process Injection via PowerShell [prebuilt-rule-1-0-2-potential-process-injection-via-powershell]

Detects the use of Windows API functions that are commonly abused by malware and security tools to load malicious code or inject the malicious code into remote processes.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-PSInject.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-PSInject.ps1)
* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1)
* [https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1558]

## Triage and analysis.

## Investigating Potential Process Injection via PowerShell

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

PowerShell also has solid capabilities to make the interaction with the Win32 API in an uncomplicated and reliable way,
like the execution of inline C# code, PSReflect, Get-ProcAddress, etc.

Red Team tooling and malware developers take advantage of these capabilities to develop stagers and loaders that inject
payloads directly into the memory without touching the disk to circumvent file-based security protections.

### Possible investigation steps

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Check if the imported function was executed and which process it targeted.
- Check if the injected code can be retrieved (hardcoded in the script or on command line logs).

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.
- Reset the password for the user account.

## Config

The 'PowerShell Script Block Logging' logging policy must be enabled.
Steps to implement the logging policy with with Advanced Audit Configuration:

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

## Rule query [_rule_query_1799]

```js
event.category:process and
  powershell.file.script_block_text : (
   (VirtualAlloc or VirtualAllocEx or VirtualProtect or LdrLoadDll or LoadLibrary or LoadLibraryA or
      LoadLibraryEx or GetProcAddress or OpenProcess or OpenProcessToken or AdjustTokenPrivileges) and
   (WriteProcessMemory or CreateRemoteThread or NtCreateThreadEx or CreateThread or QueueUserAPC or
      SuspendThread or ResumeThread or GetDelegateForFunctionPointer)
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Dynamic-link Library Injection
    * ID: T1055.001
    * Reference URL: [https://attack.mitre.org/techniques/T1055/001/](https://attack.mitre.org/techniques/T1055/001/)

* Sub-technique:

    * Name: Portable Executable Injection
    * ID: T1055.002
    * Reference URL: [https://attack.mitre.org/techniques/T1055/002/](https://attack.mitre.org/techniques/T1055/002/)



