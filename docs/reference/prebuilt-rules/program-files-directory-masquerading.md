---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/program-files-directory-masquerading.html
---

# Program Files Directory Masquerading [program-files-directory-masquerading]

Identifies execution from a directory masquerading as the Windows Program Files directories. These paths are trusted and usually host trusted third party programs. An adversary may leverage masquerading, along with low privileges to bypass detections allowlisting those folders.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

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
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_842]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Program Files Directory Masquerading**

The Program Files directories in Windows are trusted locations for legitimate software. Adversaries may exploit this trust by creating similarly named directories to execute malicious files, bypassing security measures. The detection rule identifies suspicious executions from these masquerading paths, excluding known legitimate directories, to flag potential threats. This helps in identifying defense evasion tactics used by attackers.

**Possible investigation steps**

* Review the process executable path to confirm if it matches any known masquerading patterns, such as unexpected directories containing "Program Files" in their path.
* Check the parent process of the suspicious executable to determine how it was launched and assess if the parent process is legitimate or potentially malicious.
* Investigate the user account associated with the process execution to determine if it has low privileges and if the activity aligns with typical user behavior.
* Correlate the event with other security logs or alerts from data sources like Microsoft Defender for Endpoint or Sysmon to identify any related suspicious activities or patterns.
* Examine the file hash of the executable to see if it matches known malware signatures or if it has been flagged in threat intelligence databases.
* Assess the network activity associated with the process to identify any unusual outbound connections that could indicate data exfiltration or command-and-control communication.

**False positive analysis**

* Legitimate software installations or updates may create temporary directories resembling Program Files paths. Users can monitor installation logs and exclude these specific paths if they are verified as part of a legitimate process.
* Some enterprise applications may use custom directories that mimic Program Files for compatibility reasons. IT administrators should document these paths and add them to the exclusion list to prevent false alerts.
* Development environments might create test directories with similar naming conventions. Developers should ensure these paths are excluded during active development phases to avoid unnecessary alerts.
* Security tools or scripts that perform regular checks or updates might execute from non-standard directories. Verify these tools and add their execution paths to the exception list if they are confirmed safe.
* Backup or recovery software might temporarily use directories that resemble Program Files for storing executable files. Confirm the legitimacy of these operations and exclude the paths if they are part of routine backup processes.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate any suspicious processes identified as executing from masquerading directories to halt any ongoing malicious actions.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious files or remnants.
* Review and restore any altered system configurations or settings to their original state to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar environments to detect any recurrence of the threat or similar tactics.
* Update security policies and access controls to prevent unauthorized creation of directories that mimic trusted paths, enhancing defenses against similar masquerading attempts.


## Rule query [_rule_query_899]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "C:\\*Program*Files*\\*.exe",
    "\\Device\\HarddiskVolume?\\*Program*Files*\\*.exe"
  ) and
  not process.executable : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Users\\*.exe",
        "?:\\ProgramData\\*.exe",
        "?:\\Windows\\Downloaded Program Files\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
  ) and
  not (
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume?\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume?\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume?\\Users\\*.exe",
        "\\Device\\HarddiskVolume?\\ProgramData\\*.exe",
        "\\Device\\HarddiskVolume?\\Windows\\Downloaded Program Files\\*.exe",
        "\\Device\\HarddiskVolume?\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "\\Device\\HarddiskVolume?\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
      )
  )
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

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)



