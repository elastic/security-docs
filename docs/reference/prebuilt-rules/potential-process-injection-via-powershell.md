---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-process-injection-via-powershell.html
---

# Potential Process Injection via PowerShell [potential-process-injection-via-powershell]

Detects the use of Windows API functions that are commonly abused by malware and security tools to load malicious code or inject it into remote processes.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-PSInject.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-PSInject.ps1)
* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1)
* [https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: PowerShell Logs

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_746]

**Triage and analysis**

**Investigating Potential Process Injection via PowerShell**

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This makes it available for use in various environments, and creates an attractive way for attackers to execute code.

PowerShell also has solid capabilities to make the interaction with the Win32 API in an uncomplicated and reliable way, like the execution of inline C# code, PSReflect, Get-ProcAddress, etc.

Red Team tooling and malware developers take advantage of these capabilities to develop stagers and loaders that inject payloads directly into the memory without touching the disk to circumvent file-based security protections.

**Possible investigation steps**

* Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Examine file or network events from the involved PowerShell process for suspicious behavior.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Evaluate whether the user needs to use PowerShell to complete tasks.
* Check if the imported function was executed and which process it targeted.
* Check if the injected code can be retrieved (hardcoded in the script or on command line logs).

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Related rules**

* PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_479]

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


## Rule query [_rule_query_794]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
   (VirtualAlloc or VirtualAllocEx or VirtualProtect or LdrLoadDll or LoadLibrary or LoadLibraryA or
      LoadLibraryEx or GetProcAddress or OpenProcess or OpenProcessToken or AdjustTokenPrivileges) and
   (WriteProcessMemory or CreateRemoteThread or NtCreateThreadEx or CreateThread or QueueUserAPC or
      SuspendThread or ResumeThread or GetDelegateForFunctionPointer)
  ) and not
  file.directory: (
    "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM" or
    "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
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



