---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-startup-shell-folder-modification.html
---

# Suspicious Startup Shell Folder Modification [prebuilt-rule-1-0-2-suspicious-startup-shell-folder-modification]

Identifies suspicious startup shell folder modifications to change the default Startup directory in order to bypass detections monitoring file creation in the Windows Startup folder.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1634]

## Triage and analysis

## Investigating Suspicious Startup Shell Folder Modification

Techniques used within malware and by adversaries often leverage the Windows registry to store malicious programs for
persistence. Startup shell folders are often targeted as they are not as prevalent as normal Startup folder paths so this
behavior may evade existing AV/EDR solutions. These programs may also run with higher privileges which can be ideal for
an attacker.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Review the source process and related file tied to the Windows Registry entry.
- Validate the activity is not related to planned patches, updates, network administrator activity or legitimate software
installations.
- Determine if activity is unique by validating if other machines in the same organization have similar entries.
- Retrieve the file and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- There is a high possibility of benign legitimate programs being added to shell folders. This activity could be based
on new software installations, patches, or other network administrator activity. Before entering further investigation,
it should be verified that this activity is not benign.

## Related rules

- Startup or Run Key Registry Modification - 97fc44d3-8dae-4019-ae83-298c3015600f
- Persistent Scripts in the Startup Directory - f7c4dc5a-a58d-491d-9f14-9b66507121c0

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Since this activity is considered post-exploitation behavior, it's important to understand how the behavior was first
initialized such as through a macro-enabled document that was attached in a phishing email. After understanding the source
of the attack, you can use this information to search for similar indicators on other machines in the same environment.

## Rule query [_rule_query_1888]

```js
registry where
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
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



