---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-startup-or-run-key-registry-modification.html
---

# Startup or Run Key Registry Modification [prebuilt-rule-8-4-2-startup-or-run-key-registry-modification]

Identifies run key or startup key registry modifications. In order to survive reboots and other system interrupts, attackers will modify run keys within the registry or leverage startup folder items as a form of persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3525]

## Triage and analysis

## Investigating Startup or Run Key Registry Modification

Adversaries may achieve persistence by referencing a program with a registry run key. Adding an entry to the run keys in the registry will cause the program referenced to be executed when a user logs in. These programs will executed under the context of the user and will have the account's permissions. This rule looks for this behavior by monitoring a range of registry run keys.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Validate if the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze the process executable using a private sandboxed analysis system.
  - Observe and collect information about the following activities in both the sandbox and the alert subject host:
    - Attempts to contact external domains and addresses.
      - Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
      - Examine the DNS cache for suspicious or anomalous entries.
        - !{osquery{"query":"SELECT * FROM dns_cache", "label":"Osquery - Retrieve DNS Cache"}}
    - Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
    - Examine the host services for suspicious or anomalous entries.
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services","label":"Osquery - Retrieve All Services"}}
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR user_account == null)","label":"Osquery - Retrieve Services Running on User Accounts"}}
      - !{osquery{"query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'","label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link"}}
  - Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target host after the registry modification.


## False positive analysis

- There is a high possibility of benign legitimate programs being added to registry run keys. This activity could be based on new software installations, patches, or any kind of network administrator related activity. Before undertaking further investigation, verify that this activity is not benign.

## Related rules

- Suspicious Startup Shell Folder Modification - c8b150f0-0164-475b-a75e-74b47800a9ff
- Persistent Scripts in the Startup Directory - f7c4dc5a-a58d-491d-9f14-9b66507121c0
- Startup Folder Persistence via Unsigned Process - 2fba96c0-ade5-4bce-b92f-a5df2509da3f
- Startup Persistence by a Suspicious Process - 440e2db4-bc7f-4c96-a068-65b78da59bde

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4208]

```js
registry where registry.data.strings != null and
 registry.path : (
     /* Machine Hive */
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",
     /* Users Hive */
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     ) and
  /* add common legitimate changes without being too restrictive as this is one of the most abused AESPs */
  not registry.data.strings : "ctfmon.exe /n" and
  not (registry.value : "Application Restart #*" and process.name : "csrss.exe") and
  user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\SysWOW64\\msiexec.exe") and
  not (process.name : "OneDriveSetup.exe" and
       registry.value : ("Delete Cached Standalone Update Binary", "Delete Cached Update Binary", "amd64", "Uninstall *") and
       registry.data.strings : "?:\\Windows\\system32\\cmd.exe /q /c * \"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\"")
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



