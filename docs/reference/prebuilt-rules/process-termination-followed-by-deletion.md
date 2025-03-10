---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/process-termination-followed-by-deletion.html
---

# Process Termination followed by Deletion [process-termination-followed-by-deletion]

Identifies a process termination event quickly followed by the deletion of its executable file. Malware tools and other non-native files dropped or created on a system by an adversary may leave traces to indicate to what occurred. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary’s footprint.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.file-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_841]

**Triage and analysis**

**Investigating Process Termination followed by Deletion**

This rule identifies an unsigned process termination event quickly followed by the deletion of its executable file. Attackers can delete programs after their execution in an attempt to cover their tracks in a host.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications, command line and any spawned child processes.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the process executable using a private sandboxed analysis system.
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
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.

**False positive analysis**

* This activity is unlikely to happen legitimately, as programs that exhibit this behavior, such as installers and similar utilities, should be signed. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_897]

```js
sequence by host.id with maxspan=5s
   [process where host.os.type == "windows" and event.type == "end" and
    process.code_signature.trusted != true and
    not process.executable like
             ("C:\\Windows\\SoftwareDistribution\\*.exe",
              "C:\\Windows\\WinSxS\\*.exe",
              "?:\\Windows\\Postillion\\Office\\*.exe") and
    not (
      process.name : "infinst.exe" and process.parent.name: "dxsetup.exe" and
      process.parent.code_signature.subject_name == "NVIDIA Corporation" and
      process.parent.code_signature.status == "trusted"
    )
   ] by process.executable
   [file where host.os.type == "windows" and event.type == "deletion" and file.extension in~ ("exe", "scr", "com") and
    not process.executable like
             ("?:\\Program Files\\*.exe",
              "?:\\Program Files (x86)\\*.exe",
              "?:\\Windows\\System32\\svchost.exe",
              "?:\\Windows\\System32\\drvinst.exe",
              "?:\\Windows\\Postillion\\Office\\*.exe") and
    not file.path like (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\Temp\\*\\DismHost.exe",
          "?:\\$WINDOWS.~BT\\Work\\*\\DismHost.exe",
          "?:\\$WinREAgent\\Scratch\\*\\DismHost.exe",
          "?:\\Windows\\tenable_mw_scan_*.exe",
          "?:\\Users\\*\\AppData\\Local\\Temp\\LogiUI\\Pak\\uninstall.exe",
          "?:\\ProgramData\\chocolatey\\*.exe"
    ) and
    not (process.name : "OktaVerifySetup-*.exe" and process.code_signature.subject_name == "Okta, Inc.") and
    not (
      process.executable : "?:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\CitrixReceiver\\*" and
      process.code_signature.subject_name == "Citrix Systems, Inc." and
      file.path : "?:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\CitrixReceiver\\*\\bootstrapperhelper.exe"
    )
   ] by file.path
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: File Deletion
    * ID: T1070.004
    * Reference URL: [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)



