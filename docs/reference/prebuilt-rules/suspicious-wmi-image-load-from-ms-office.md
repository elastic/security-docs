---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-wmi-image-load-from-ms-office.html
---

# Suspicious WMI Image Load from MS Office [suspicious-wmi-image-load-from-ms-office]

Identifies a suspicious image load (wmiutils.dll) from Microsoft Office processes. This behavior may indicate adversarial activity where child processes are spawned via Windows Management Instrumentation (WMI). This technique can be used to execute code and evade traditional parent/child processes spawned from Microsoft Office products.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.library-*
* logs-windows.sysmon_operational-*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1041]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious WMI Image Load from MS Office**

Windows Management Instrumentation (WMI) is a powerful framework for managing data and operations on Windows systems. Adversaries exploit WMI to execute code stealthily, bypassing traditional security measures by spawning processes indirectly. The detection rule identifies unusual loading of the `wmiutils.dll` library by Microsoft Office applications, signaling potential misuse of WMI for malicious execution. This rule leverages event categories and process names to pinpoint suspicious activity, aiding in early threat detection.

**Possible investigation steps**

* Review the alert details to confirm the specific Microsoft Office process involved (e.g., WINWORD.EXE, EXCEL.EXE) and the associated event category (library, driver, or process).
* Check the process execution history to determine if the process has a legitimate reason to load the wmiutils.dll library, such as recent updates or legitimate automation tasks.
* Investigate the parent process of the flagged Microsoft Office application to identify any unusual or unexpected parent-child process relationships that could indicate malicious activity.
* Analyze recent user activity on the affected system to identify any suspicious behavior or unauthorized access that might correlate with the alert.
* Examine network connections and data transfers initiated by the flagged process to detect any potential data exfiltration or communication with known malicious IP addresses.
* Cross-reference the alert with other security logs and alerts to identify any patterns or additional indicators of compromise that might suggest a broader attack campaign.

**False positive analysis**

* Legitimate use of WMI by Microsoft Office applications for automation tasks or system management can trigger the rule. Users should verify if the activity aligns with expected administrative tasks.
* Some third-party plugins or add-ins for Microsoft Office may load wmiutils.dll for legitimate purposes. Users can create exceptions for these known plugins after confirming their benign nature.
* Scheduled tasks or scripts that utilize WMI for legitimate business processes might cause false positives. Review and document these processes, then exclude them from the rule if they are verified as non-threatening.
* Security or monitoring tools that interact with Office applications and use WMI for data collection could be flagged. Ensure these tools are recognized and excluded from the rule after validation.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious Microsoft Office processes identified in the alert that are loading the `wmiutils.dll` library.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious code or files.
* Review and analyze the system’s WMI repository and scripts for unauthorized or suspicious entries, and remove any that are identified as malicious.
* Restore the system from a known good backup if malicious activity has compromised system integrity or data.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for WMI activity and Microsoft Office processes to detect similar threats in the future.


## Setup [_setup_655]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1094]

```js
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



