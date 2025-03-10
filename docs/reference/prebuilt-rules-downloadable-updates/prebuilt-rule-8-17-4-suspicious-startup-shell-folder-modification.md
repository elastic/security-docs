---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-startup-shell-folder-modification.html
---

# Suspicious Startup Shell Folder Modification [prebuilt-rule-8-17-4-suspicious-startup-shell-folder-modification]

Identifies suspicious startup shell folder modifications to change the default Startup directory in order to bypass detections monitoring file creation in the Windows Startup folder.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign](https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign)
* [https://www.elastic.co/security-labs/revisiting-blister-new-developments-of-the-blister-loader](https://www.elastic.co/security-labs/revisiting-blister-new-developments-of-the-blister-loader)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4909]

**Triage and analysis**

**Investigating Suspicious Startup Shell Folder Modification**

Techniques used within malware and by adversaries often leverage the Windows registry to store malicious programs for persistence. Startup shell folders are often targeted as they are not as prevalent as normal Startup folder paths so this behavior may evade existing AV/EDR solutions. These programs may also run with higher privileges which can be ideal for an attacker.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Review the source process and related file tied to the Windows Registry entry.
* Validate if the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* Examine the host for derived artifacts that indicate suspicious activities:
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
* Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target host after the registry modification.

**False positive analysis**

* There is a high possibility of benign legitimate programs being added to shell folders. This activity could be based on new software installations, patches, or other network administrator activity. Before undertaking further investigation, it should be verified that this activity is not benign.

**Related rules**

* Startup or Run Key Registry Modification - 97fc44d3-8dae-4019-ae83-298c3015600f
* Persistent Scripts in the Startup Directory - f7c4dc5a-a58d-491d-9f14-9b66507121c0

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* If the malicious file was delivered via phishing:
* Block the email sender from sending future emails.
* Block the malicious web pages.
* Remove emails from the sender from mailboxes.
* Consider improvements to the security awareness program.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_5864]

```js
registry where host.os.type == "windows" and event.type == "change" and
 registry.value : ("Common Startup", "Startup") and
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) and
  registry.data.strings != null and
  /* Normal Startup Folder Paths */
  not registry.data.strings : (
           "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
           )
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

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



