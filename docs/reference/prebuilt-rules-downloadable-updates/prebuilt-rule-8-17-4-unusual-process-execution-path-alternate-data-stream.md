---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-process-execution-path-alternate-data-stream.html
---

# Unusual Process Execution Path - Alternate Data Stream [prebuilt-rule-8-17-4-unusual-process-execution-path-alternate-data-stream]

Identifies processes running from an Alternate Data Stream. This is uncommon for legitimate processes and sometimes done by adversaries to hide malware.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
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
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4814]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Process Execution Path - Alternate Data Stream**

Alternate Data Streams (ADS) in Windows allow files to contain multiple data streams, which can be exploited by adversaries to conceal malicious code. This technique is often used for defense evasion, as it hides malware within legitimate files. The detection rule identifies processes initiated from ADS by monitoring specific execution patterns, such as unique argument structures, to flag potential threats.

**Possible investigation steps**

* Review the process details, including the process name and path, to determine if it is a known legitimate application or potentially malicious.
* Examine the process arguments, specifically looking for the pattern "?:\*:*", to understand the context of the execution and identify any suspicious or unusual characteristics.
* Check the parent process of the flagged process to assess if it was initiated by a legitimate or expected source.
* Investigate the user account associated with the process execution to determine if the activity aligns with the user’s typical behavior or if it appears anomalous.
* Correlate the event with other security logs or alerts from data sources like Sysmon, Microsoft Defender for Endpoint, or Crowdstrike to gather additional context and identify any related suspicious activities.
* Search for any known indicators of compromise (IOCs) related to the process or file path in threat intelligence databases to assess if the activity is associated with known threats.

**False positive analysis**

* Legitimate software installations or updates may use alternate data streams to execute processes. Users can create exceptions for known software update paths to prevent unnecessary alerts.
* Some backup or file synchronization tools might utilize alternate data streams for metadata storage. Identify these tools and exclude their execution paths from the detection rule.
* Certain system administration scripts or tools may leverage alternate data streams for legitimate purposes. Review and whitelist these scripts if they are verified as non-threatening.
* Developers might use alternate data streams during software development for testing purposes. Ensure development environments are accounted for in the exception list to avoid false positives.
* Security tools themselves may use alternate data streams for scanning or monitoring activities. Verify and exclude these tools from the detection rule to reduce noise.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malware.
* Terminate any suspicious processes identified as running from an Alternate Data Stream to halt malicious activity.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any hidden malware.
* Examine the file system for any additional Alternate Data Streams and remove or quarantine any suspicious files.
* Restore any affected files or systems from known good backups to ensure system integrity.
* Monitor the network for any unusual outbound traffic from the affected system that may indicate data exfiltration attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are compromised.


## Rule query [_rule_query_5769]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.args : "?:\\*:*" and process.args_count == 1
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: NTFS File Attributes
    * ID: T1564.004
    * Reference URL: [https://attack.mitre.org/techniques/T1564/004/](https://attack.mitre.org/techniques/T1564/004/)



