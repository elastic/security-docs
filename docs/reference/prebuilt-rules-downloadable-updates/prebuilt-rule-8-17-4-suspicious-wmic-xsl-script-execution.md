---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-wmic-xsl-script-execution.html
---

# Suspicious WMIC XSL Script Execution [prebuilt-rule-8-17-4-suspicious-wmic-xsl-script-execution]

Identifies WMIC allowlist bypass techniques by alerting on suspicious execution of scripts. When WMIC loads scripting libraries it may be indicative of an allowlist bypass.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.library-*
* logs-windows.sysmon_operational-*

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
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4807]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious WMIC XSL Script Execution**

Windows Management Instrumentation Command-line (WMIC) is a powerful tool for managing Windows systems. Adversaries exploit WMIC to bypass security measures by executing scripts via XSL files, often loading scripting libraries like jscript.dll or vbscript.dll. The detection rule identifies such suspicious activities by monitoring WMIC executions with atypical arguments and the loading of specific libraries, indicating potential misuse for defense evasion.

**Possible investigation steps**

* Review the process execution details to confirm the presence of WMIC.exe or wmic.exe with suspicious arguments such as "format*:*", "/format*:*", or "**-format**:*" that deviate from typical usage patterns.
* Examine the command line used in the process execution to identify any unusual or unexpected parameters that could indicate malicious intent, excluding known benign patterns like "* /format:table *".
* Investigate the sequence of events to determine if there was a library or process event involving the loading of jscript.dll or vbscript.dll, which may suggest script execution through XSL files.
* Correlate the process.entity_id with other related events within the 2-minute window to identify any additional suspicious activities or processes that may have been spawned as a result of the initial execution.
* Check the parent process of the suspicious WMIC execution to understand the context and origin of the activity, which may provide insights into whether it was initiated by a legitimate application or a potentially malicious actor.
* Analyze the host’s recent activity and security logs for any other indicators of compromise or related suspicious behavior that could be part of a broader attack campaign.

**False positive analysis**

* Legitimate administrative tasks using WMIC with custom scripts may trigger alerts. Review the command line arguments and context to determine if the execution is part of routine system management.
* Automated scripts or software updates that utilize WMIC for legitimate purposes might load scripting libraries like jscript.dll or vbscript.dll. Identify these processes and consider adding them to an allowlist to prevent future false positives.
* Security tools or monitoring solutions that use WMIC for system checks can be mistaken for suspicious activity. Verify the source and purpose of the execution and exclude these known tools from triggering alerts.
* Scheduled tasks or maintenance scripts that use WMIC with non-standard arguments could be flagged. Document these tasks and create exceptions for their specific command line patterns to reduce noise.
* Custom applications developed in-house that rely on WMIC for functionality may inadvertently match the detection criteria. Work with development teams to understand these applications and adjust the detection rule to accommodate their legitimate use cases.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious WMIC processes identified by the alert to stop ongoing malicious script execution.
* Conduct a thorough review of the system’s recent activity logs to identify any additional indicators of compromise or related malicious activities.
* Remove any unauthorized or suspicious XSL files and associated scripts from the system to prevent re-execution.
* Restore the system from a known good backup if any critical system files or configurations have been altered.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_5762]

```js
sequence by process.entity_id with maxspan = 2m
[process where host.os.type == "windows" and event.type == "start" and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : ("* /format:table *", "* /format:table")]
[any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : ("jscript.dll", "vbscript.dll") or file.name : ("jscript.dll", "vbscript.dll"))]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: XSL Script Processing
    * ID: T1220
    * Reference URL: [https://attack.mitre.org/techniques/T1220/](https://attack.mitre.org/techniques/T1220/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



