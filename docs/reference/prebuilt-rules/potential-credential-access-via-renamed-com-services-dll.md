---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-credential-access-via-renamed-com-services-dll.html
---

# Potential Credential Access via Renamed COM+ Services DLL [potential-credential-access-via-renamed-com-services-dll]

Identifies suspicious renamed COMSVCS.DLL Image Load, which exports the MiniDump function that can be used to dump a process memory. This may indicate an attempt to dump LSASS memory while bypassing command-line based detection in preparation for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Defense Evasion
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_660]

**Triage and analysis**

**Investigating Potential Credential Access via Renamed COM+ Services DLL**

COMSVCS.DLL is a Windows library that exports the MiniDump function, which can be used to dump a process memory. Adversaries may attempt to dump LSASS memory using a renamed COMSVCS.DLL to bypass command-line based detection and gain unauthorized access to credentials.

This rule identifies suspicious instances of rundll32.exe loading a renamed COMSVCS.DLL image, which can indicate potential abuse of the MiniDump function for credential theft.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate any abnormal behavior by the subject process, such as network connections, registry or file modifications, and any spawned child processes.
* Identify the process that created the DLL using file creation events.
* Inspect the file for useful metadata, such as file size and creation or modification time.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the process executable and DLL using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process’s `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* Look for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems.

**False positive analysis**

* False positives may include legitimate instances of rundll32.exe loading a renamed COMSVCS.DLL image for non-malicious purposes, such as during software development, testing, or troubleshooting.

**Related Rules**

* Potential Credential Access via LSASS Memory Dump - 9960432d-9b26-409f-972b-839a959e79e2
* Suspicious Module Loaded by LSASS - 3a6001a0-0939-4bbe-86f4-47d8faeb7b97
* Suspicious Lsass Process Access - 128468bf-cab1-4637-99ea-fdf3780a4609
* LSASS Process Access via Windows API - ff4599cb-409f-4910-a239-52e4e6f532ff

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Implement Elastic Endpoint Security to detect and prevent further post exploitation activities in the environment.
* Contain the affected system by isolating it from the network to prevent further spread of the attack.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Restore the affected system to its operational state by applying any necessary patches, updates, or configuration changes.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_421]

**Setup**

You will need to enable logging of ImageLoads in your Sysmon configuration to include COMSVCS.DLL by Imphash or Original File Name.


## Rule query [_rule_query_703]

```js
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.category == "process" and
    process.name : "rundll32.exe"]
 [process where host.os.type == "windows" and event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
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

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)



