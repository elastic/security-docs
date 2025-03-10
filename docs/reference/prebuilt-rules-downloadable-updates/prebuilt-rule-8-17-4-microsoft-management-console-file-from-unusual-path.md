---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-management-console-file-from-unusual-path.html
---

# Microsoft Management Console File from Unusual Path [prebuilt-rule-8-17-4-microsoft-management-console-file-from-unusual-path]

Identifies attempts to open a Microsoft Management Console File from untrusted paths. Adversaries may use MSC files for initial access and execution.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.*
* endgame-*
* logs-system.security*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/grimresource](https://www.elastic.co/security-labs/grimresource)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Data Source: System
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 308

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4859]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Management Console File from Unusual Path**

Microsoft Management Console (MMC) is a Windows utility that provides a framework for system management. Adversaries may exploit MMC by executing .msc files from non-standard directories to bypass security controls. The detection rule identifies such anomalies by monitoring the execution of mmc.exe with .msc files from untrusted paths, flagging potential unauthorized access or execution attempts.

**Possible investigation steps**

* Review the process execution details to confirm the path of the mmc.exe and the .msc file being executed. Check if the path is indeed non-standard or untrusted as per the query criteria.
* Investigate the origin of the .msc file by examining file creation and modification timestamps, and check for any recent changes or unusual activity in the directory where the file resides.
* Analyze the user account associated with the process execution to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Check for any related alerts or logs around the same timeframe that might indicate lateral movement or other malicious activities, such as unusual network connections or file access patterns.
* Correlate the event with other data sources mentioned in the rule, such as Microsoft Defender for Endpoint or Crowdstrike, to gather additional context or corroborating evidence of potential malicious activity.
* Assess the risk and impact of the execution by determining if the .msc file has any known malicious signatures or if it attempts to perform unauthorized actions on the system.

**False positive analysis**

* Legitimate administrative tasks may trigger this rule if system administrators execute .msc files from custom directories. To manage this, create exceptions for known administrative scripts or tools that are regularly used from non-standard paths.
* Software installations or updates might involve executing .msc files from temporary or installation directories. Monitor these activities and whitelist specific installation paths if they are verified as safe and part of routine operations.
* Automated scripts or third-party management tools could execute .msc files from non-standard locations as part of their normal operation. Identify these tools and add their execution paths to the exception list to prevent unnecessary alerts.
* Development or testing environments may involve running .msc files from various directories for testing purposes. Establish a separate monitoring policy for these environments or exclude known development paths to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes related to mmc.exe executing from untrusted paths to halt potential malicious activity.
* Conduct a thorough review of the system’s recent activity logs to identify any additional indicators of compromise or related suspicious activities.
* Remove any unauthorized .msc files found in non-standard directories and ensure they are not reintroduced.
* Restore the system from a known good backup if any unauthorized changes or damage is detected.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_5814]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "?:\\Windows\\System32\\mmc.exe",
    "\\Device\\HarddiskVolume?\\Windows\\System32\\mmc.exe"
  ) and
  process.args : "*.msc" and
  not process.args : (
        "?:\\Windows\\System32\\*.msc",
        "?:\\Windows\\SysWOW64\\*.msc",
        "?:\\Program files\\*.msc",
        "?:\\Program Files (x86)\\*.msc"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)

* Sub-technique:

    * Name: JavaScript
    * ID: T1059.007
    * Reference URL: [https://attack.mitre.org/techniques/T1059/007/](https://attack.mitre.org/techniques/T1059/007/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: MMC
    * ID: T1218.014
    * Reference URL: [https://attack.mitre.org/techniques/T1218/014/](https://attack.mitre.org/techniques/T1218/014/)



