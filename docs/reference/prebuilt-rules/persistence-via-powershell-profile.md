---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-powershell-profile.html
---

# Persistence via PowerShell profile [persistence-via-powershell-profile]

Identifies the creation or modification of a PowerShell profile. PowerShell profile is a script that is executed when PowerShell starts to customize the user environment, which can be abused by attackers to persist in a environment where PowerShell is common.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
* [https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/)

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

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_626]

**Triage and analysis**

**Investigating Persistence via PowerShell profile**

PowerShell profiles are scripts executed when PowerShell starts, customizing the user environment. They are commonly used in Windows environments for legitimate purposes, such as setting variables or loading modules. However, adversaries can abuse PowerShell profiles to establish persistence by inserting malicious code that executes each time PowerShell is launched.

This rule identifies the creation or modification of a PowerShell profile. It does this by monitoring file events on Windows systems, specifically targeting profile-related file paths and names, such as `profile.ps1` and `Microsoft.Powershell_profile.ps1`. By detecting these activities, security analysts can investigate potential abuse of PowerShell profiles for malicious persistence.

[TBC: QUOTE]
**Possible investigation steps**

* Retrive and inspect the PowerShell profile content; look for suspicious DLL imports, collection or persistence capabilities, suspicious functions, encoded or compressed data, suspicious commands, and other potentially malicious characteristics.
* Identify the process responsible for the PowerShell profile creation/modification. Use the Elastic Defend events to examine all the activity of the subject process by filtering by the process’s `process.entity_id`.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Evaluate whether the user needs to use PowerShell to complete tasks.
* Check for additional PowerShell and command-line logs that indicate that any suspicious command or function were run.
* Examine the host for derived artifacts that indicate suspicious activities:
* Observe and collect information about the following activities in the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process’s `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}

**False positive analysis**

* This is a dual-use mechanism, meaning its usage is not inherently malicious. Analysts can dismiss the alert if the script doesn’t contain malicious functions or potential for abuse, no other suspicious activity was identified, and the user has business justifications to use PowerShell.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Isolate the involved hosts to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Reimage the host operating system or restore the compromised files to clean versions.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
* Consider enabling and collecting PowerShell logs such as transcription, module, and script block logging, to improve visibility into PowerShell activities.


## Rule query [_rule_query_668]

```js
file where host.os.type == "windows" and event.type != "deletion" and
  file.path : ("?:\\Users\\*\\Documents\\WindowsPowerShell\\*",
               "?:\\Users\\*\\Documents\\PowerShell\\*",
               "?:\\Windows\\System32\\WindowsPowerShell\\*") and
  file.name : ("profile.ps1", "Microsoft.Powershell_profile.ps1")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: PowerShell Profile
    * ID: T1546.013
    * Reference URL: [https://attack.mitre.org/techniques/T1546/013/](https://attack.mitre.org/techniques/T1546/013/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: PowerShell Profile
    * ID: T1546.013
    * Reference URL: [https://attack.mitre.org/techniques/T1546/013/](https://attack.mitre.org/techniques/T1546/013/)



