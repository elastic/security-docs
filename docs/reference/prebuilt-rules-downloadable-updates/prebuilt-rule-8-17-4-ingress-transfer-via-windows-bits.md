---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ingress-transfer-via-windows-bits.html
---

# Ingress Transfer via Windows BITS [prebuilt-rule-8-17-4-ingress-transfer-via-windows-bits]

Identifies downloads of executable and archive files via the Windows Background Intelligent Transfer Service (BITS). Adversaries could leverage Windows BITS transfer jobs to download remote payloads.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4690]

**Triage and analysis**

**Investigating Ingress Transfer via Windows BITS**

Windows Background Intelligent Transfer Service (BITS) is a technology that allows the transfer of files between a client and a server, which makes it a dual-use mechanism, being used by both legitimate apps and attackers. When malicious applications create BITS jobs, files are downloaded or uploaded in the context of the service host process, which can bypass security protections, and it helps to obscure which application requested the transfer.

This rule identifies such abuse by monitoring for file renaming events involving "svchost.exe" and "BIT*.tmp" on Windows systems.

[TBC: QUOTE]
**Possible investigation steps**

* Gain context into the BITS transfer.
* Try to determine the process that initiated the BITS transfer.
* Search `bitsadmin.exe` processes and examine their command lines.
* Look for unusual processes loading `Bitsproxy.dll` and other BITS-related DLLs.
* Try to determine the origin of the file.
* Inspect network connections initiated by `svchost.exe`.
* Inspect `Microsoft-Windows-Bits-Client/Operational` Windows logs, specifically the event ID 59, for unusual events.
* Velociraptor can be used to extract these entries using the [bitsadmin artifact](https://docs.velociraptor.app/exchange/artifacts/pages/bitsadmin/).
* Check the reputation of the remote server involved in the BITS transfer, such as its IP address or domain, using threat intelligence platforms or online reputation services.
* Check if the domain is newly registered or unexpected.
* Use the identified domain as an indicator of compromise (IoCs) to scope other compromised hosts in the environment.
* [BitsParser](https://github.com/fireeye/BitsParser) can be used to parse BITS database files to extract BITS job information.
* Examine the details of the dropped file, and whether it was executed.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the involved executables using a private sandboxed analysis system.
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

**False positive analysis**

* Known false positives for the rule include legitimate software and system updates that use BITS for downloading files.

**Related Rules**

* Persistence via BITS Job Notify Cmdline - c3b915e0-22f3-4bf7-991d-b643513c722f
* Unsigned BITS Service Client Process - 9a3884d0-282d-45ea-86ce-b9c81100f026
* Bitsadmin Activity - 8eec4df1-4b4b-4502-b6c3-c788714604c9

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Isolate the involved hosts to prevent further post-compromise behavior.
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


## Rule query [_rule_query_5645]

```js
file where host.os.type == "windows" and event.action == "rename" and
  process.name : "svchost.exe" and file.Ext.original.name : "BIT*.tmp" and
  (file.extension : ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") or
   file.Ext.header_bytes : "4d5a*") and

  /* noisy paths, for hunting purposes you can use the same query without the following exclusions */
  not file.path : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\*", "?:\\ProgramData\\*\\*") and

  /* lot of third party SW use BITS to download executables with a long file name */
  not length(file.name) > 30 and
  not file.path : (
        "?:\\Users\\*\\AppData\\Local\\Temp*\\wct*.tmp",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\RdrServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\AcroServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Docker Desktop Installer\\update-*.exe"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)



