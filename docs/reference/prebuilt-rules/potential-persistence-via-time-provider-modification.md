---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-persistence-via-time-provider-modification.html
---

# Potential Persistence via Time Provider Modification [potential-persistence-via-time-provider-modification]

Identifies modification of the Time Provider. Adversaries may establish persistence by registering and enabling a malicious DLL as a time provider. Windows uses the time provider architecture to obtain accurate time stamps from other network devices or clients in the network. Time providers are implemented in the form of a DLL file which resides in the System32 folder. The service W32Time initiates during the startup of Windows and loads w32time.dll.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/2019/10/22/persistence-time-providers/](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_724]

**Triage and analysis**

**Investigating Potential Persistence via Time Provider Modification**

The Time Provider architecture in Windows is responsible for obtaining accurate timestamps from network devices or clients. It is implemented as a DLL file in the System32 folder and is initiated by the W32Time service during Windows startup. Adversaries may exploit this by registering and enabling a malicious DLL as a time provider to establish persistence.

This rule identifies changes in the registry paths associated with Time Providers, specifically targeting the addition of new DLL files.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Examine whether the DLL is signed.
* Retrieve the DLL and determine if it is malicious:
* Analyze the file using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Restore Time Provider settings to the desired state.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_771]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path: (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*",
    "MACHINE\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*"
  ) and
  registry.data.strings:"*.dll" and
  not
  (
    process.executable : "?:\\Windows\\System32\\msiexec.exe" and
    registry.data.strings : "?:\\Program Files\\VMware\\VMware Tools\\vmwTimeProvider\\vmwTimeProvider.dll"
  ) and
  not registry.data.strings : "C:\\Windows\\SYSTEM32\\w32time.DLL"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Time Providers
    * ID: T1547.003
    * Reference URL: [https://attack.mitre.org/techniques/T1547/003/](https://attack.mitre.org/techniques/T1547/003/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Time Providers
    * ID: T1547.003
    * Reference URL: [https://attack.mitre.org/techniques/T1547/003/](https://attack.mitre.org/techniques/T1547/003/)



