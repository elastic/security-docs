---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-invoke-ninjacopy-script.html
---

# PowerShell Invoke-NinjaCopy script [powershell-invoke-ninjacopy-script]

Detects PowerShell scripts that contain the default exported functions used on Invoke-NinjaCopy. Attackers can use Invoke-NinjaCopy to read SYSTEM files that are normally locked, such as the NTDS.dit file or registry hives.

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

* [https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/collection/Invoke-NinjaCopy.ps1](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/collection/Invoke-NinjaCopy.ps1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_796]

**Triage and analysis**

**Investigating PowerShell Invoke-NinjaCopy script**

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, making it available for use in various environments, creating an attractive way for attackers to execute code.

Invoke-NinjaCopy is a PowerShell script capable of reading SYSTEM files that were normally locked, such as `NTDS.dit` or sensitive registry locations. It does so by using the direct volume access technique, which enables attackers to bypass access control mechanisms and file system monitoring by reading the raw data directly from the disk and extracting the file by parsing the file system structures.

**Possible investigation steps**

* Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Examine file or network events from the involved PowerShell process for suspicious behavior.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Evaluate whether the user needs to use PowerShell to complete tasks.
* Determine whether the script stores the captured data locally.
* Check if the imported function was executed and which file it targeted.

**False positive analysis**

* This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_844]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "StealthReadFile" or
    "StealthReadFileAddr" or
    "StealthCloseFileDelegate" or
    "StealthOpenFile" or
    "StealthCloseFile" or
    "StealthReadFile" or
    "Invoke-NinjaCopy"
   )
  and not user.id : "S-1-5-18"
  and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)

* Sub-technique:

    * Name: NTDS
    * ID: T1003.003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/003/](https://attack.mitre.org/techniques/T1003/003/)

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Direct Volume Access
    * ID: T1006
    * Reference URL: [https://attack.mitre.org/techniques/T1006/](https://attack.mitre.org/techniques/T1006/)



