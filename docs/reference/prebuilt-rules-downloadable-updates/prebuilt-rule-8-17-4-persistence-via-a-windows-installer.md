---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-persistence-via-a-windows-installer.html
---

# Persistence via a Windows Installer [prebuilt-rule-8-17-4-persistence-via-a-windows-installer]

Identifies when the Windows installer process msiexec.exe creates a new persistence entry via scheduled tasks or startup.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
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
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4917]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via a Windows Installer**

Windows Installer, through msiexec.exe, facilitates software installation and configuration. Adversaries exploit this by creating persistence mechanisms, such as scheduled tasks or startup entries, to maintain access. The detection rule identifies suspicious activity by monitoring msiexec.exe for file creation in startup directories or registry modifications linked to auto-run keys, signaling potential persistence tactics.

**Possible investigation steps**

* Review the alert details to identify the specific file path or registry path involved in the suspicious activity, focusing on the paths specified in the query such as "?:\\Windows\\System32\\Tasks\*" or "H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*".
* Check the creation or modification timestamps of the files or registry entries to determine when the suspicious activity occurred and correlate it with other events or logs around the same time.
* Investigate the parent process of msiexec.exe to understand how it was executed and whether it was initiated by a legitimate user action or another suspicious process.
* Examine the contents of the created or modified files or registry entries to identify any scripts, executables, or commands that may indicate malicious intent.
* Look for any associated network activity or connections initiated by msiexec.exe or related processes to identify potential command and control communication.
* Cross-reference the involved file or registry paths with known indicators of compromise or threat intelligence sources to assess the risk level and potential threat actor involvement.
* If applicable, isolate the affected system and perform a deeper forensic analysis to uncover any additional persistence mechanisms or lateral movement within the network.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule when msiexec.exe creates scheduled tasks or startup entries. Users can create exceptions for known software vendors or specific installation paths to reduce noise.
* System administrators might use msiexec.exe for deploying software across the network, which can appear as suspicious activity. To handle this, exclude specific administrative accounts or IP ranges from the rule.
* Some enterprise management tools may utilize msiexec.exe for legitimate configuration changes, including registry modifications. Identify and exclude these tools by their process names or associated registry paths.
* Automated scripts or deployment tools that rely on msiexec.exe for software management can generate false positives. Consider excluding these scripts or tools by their execution context or associated file paths.
* Regularly review and update the exclusion list to ensure it aligns with the current software deployment and management practices within the organization.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate the msiexec.exe process if it is confirmed to be involved in creating unauthorized persistence mechanisms.
* Remove any scheduled tasks or startup entries created by msiexec.exe that are identified as malicious or unauthorized.
* Restore any modified registry keys to their original state if they were altered to establish persistence.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Review and update security policies to restrict the use of msiexec.exe for non-administrative users, reducing the risk of exploitation.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_5872]

```js
any where host.os.type == "windows" and
 (process.name : "msiexec.exe" or Effective_process.name : "msiexec.exe") and
 (
  (event.category == "file" and event.action == "creation" and
   file.path : ("?:\\Windows\\System32\\Tasks\\*",
                "?:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\*",
                "?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")) or

  (event.category == "registry" and event.action == "modification" and
   registry.path : ("H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                    "H*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                    "H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                    "H*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*"))
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



