---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-network-logon-provider-registry-modification.html
---

# Network Logon Provider Registry Modification [prebuilt-rule-8-17-4-network-logon-provider-registry-modification]

Identifies the modification of the network logon provider registry. Adversaries may register a rogue network logon provider module for persistence and/or credential access via intercepting the authentication credentials in clear text during user logon.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)
* [https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify](https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 214

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4726]

**Triage and analysis**

**Investigating Network Logon Provider Registry Modification**

Network logon providers are components in Windows responsible for handling the authentication process during a network logon.

This rule identifies the modification of the network logon provider registry. Adversaries may register a rogue network logon provider module for persistence and/or credential access via intercepting the authentication credentials in plain text during user logon.

[TBC: QUOTE]
**Possible investigation steps**

* Examine the `registry.data.strings` field to identify the DLL registered.
* Identify the process responsible for the registry operation and the file creation and investigate their process execution chains (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Investigate any abnormal behavior by the subject process, such as network connections, DLLs loaded, registry or file modifications, and any spawned child processes.
* Retrieve the file and examine if it is signed with valid digital signatures from vendors that are supposed to implement this kind of software and approved to use in the environment. Check for prevalence in the environment and whether they are located in expected locations.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the executables of the processes using a private sandboxed analysis system.
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

* False Positives can include legitimate software installations or updates that modify the network logon provider registry. These modifications may be necessary for the proper functioning of the software and are not indicative of malicious activity.

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Reimage the host operating system or restore the compromised files to clean versions.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_5681]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.data.strings : "?*" and registry.value : "ProviderPath" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath"
  ) and
  /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
  not (
    user.id : "S-1-5-18" and
    registry.data.strings : (
        "%SystemRoot%\\System32\\ntlanman.dll",
        "%SystemRoot%\\System32\\drprov.dll",
        "%SystemRoot%\\System32\\davclnt.dll",
        "%SystemRoot%\\System32\\vmhgfs.dll",
        "?:\\Program Files (x86)\\Citrix\\ICA Client\\x64\\pnsson.dll",
        "?:\\Program Files\\Dell\\SARemediation\\agent\\DellMgmtNP.dll",
        "?:\\Program Files (x86)\\CheckPoint\\Endpoint Connect\\\\epcgina.dll"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



