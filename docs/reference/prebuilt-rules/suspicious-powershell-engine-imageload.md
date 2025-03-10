---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-powershell-engine-imageload.html
---

# Suspicious PowerShell Engine ImageLoad [suspicious-powershell-engine-imageload]

Identifies the PowerShell engine being invoked by unexpected processes. Rather than executing PowerShell functionality with powershell.exe, some attackers do this to operate more stealthily.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit](https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1017]

**Triage and analysis**

**Investigating Suspicious PowerShell Engine ImageLoad**

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell without having to execute `PowerShell.exe` directly. This technique, often called "PowerShell without PowerShell," works by using the underlying System.Management.Automation namespace and can bypass application allowlisting and PowerShell security features.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file modifications, and any spawned child processes.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Inspect the host for suspicious or abnormal behavior in the alert timeframe.
* Retrieve the implementation (DLL, executable, etc.) and determine if it is malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* File and registry access, modification, and creation activities.
* Service creation and launch activities.
* Scheduled task creation.
* Use the PowerShell `Get-FileHash` cmdlet to get the files' SHA-256 hash values.
* Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* This activity can happen legitimately. Some vendors have their own PowerShell implementations that are shipped with some products. These benign true positives (B-TPs) can be added as exceptions if necessary after analysis.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1068]

```js
host.os.type:windows and event.category:library and
  dll.name:("System.Management.Automation.dll" or "System.Management.Automation.ni.dll") and
  not (
    process.code_signature.subject_name:("Microsoft Corporation" or "Microsoft Dynamic Code Publisher" or "Microsoft Windows") and process.code_signature.trusted:true and not process.name.caseless:("regsvr32.exe" or "rundll32.exe")
  ) and
  not (
    process.executable.caseless:(C\:\\Program*Files*\(x86\)\\*.exe or C\:\\Program*Files\\*.exe) and
    process.code_signature.trusted:true
  ) and
  not (
    process.executable.caseless: C\:\\Windows\\Lenovo\\*.exe and process.code_signature.subject_name:"Lenovo" and
    process.code_signature.trusted:true
  ) and
  not (
    process.executable.caseless: "C:\\ProgramData\\chocolatey\\choco.exe" and
    process.code_signature.subject_name:"Chocolatey Software, Inc." and process.code_signature.trusted:true
  ) and not process.executable.caseless : "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
```

**Framework**: MITRE ATT&CKTM

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



