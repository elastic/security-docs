---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/control-panel-process-with-unusual-arguments.html
---

# Control Panel Process with Unusual Arguments [control-panel-process-with-unusual-arguments]

Identifies unusual instances of Control Panel with suspicious keywords or paths in the process command line value. Adversaries may abuse control.exe to proxy execution of malicious code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.joesandbox.com/analysis/476188/1/html](https://www.joesandbox.com/analysis/476188/1/html)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_236]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Control Panel Process with Unusual Arguments**

The Control Panel in Windows is a system utility that allows users to view and adjust system settings. Adversaries may exploit this by using control.exe to execute malicious code under the guise of legitimate processes. The detection rule identifies anomalies in command-line arguments, such as unexpected file types or suspicious paths, which may indicate an attempt to evade defenses or execute unauthorized actions.

**Possible investigation steps**

* Review the command line arguments of the control.exe process to identify any unusual file types or suspicious paths, such as image file extensions or paths like **/AppData/Local/**.
* Check the parent process of control.exe to determine if it was spawned by a legitimate application or a potentially malicious one.
* Investigate the user account associated with the process to verify if the activity aligns with their typical behavior or if it appears suspicious.
* Examine recent file modifications or creations in directories like \AppData\Local\ or \Users\Public\ to identify any unauthorized or unexpected changes.
* Correlate the event with other security alerts or logs from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context on the potential threat.
* Assess the network activity of the host during the time of the alert to identify any unusual outbound connections that may indicate data exfiltration or command and control communication.

**False positive analysis**

* Image file paths in command-line arguments may trigger false positives if users or applications are legitimately accessing image files through control.exe. To mitigate this, create exceptions for known applications or user activities that frequently access image files.
* Paths involving AppData or Users\Public directories might be flagged if legitimate software installations or updates use these locations. Review and whitelist specific software processes that are known to use these directories for legitimate purposes.
* Relative path traversal patterns like ../../.. could be used by legitimate scripts or applications for configuration purposes. Identify and exclude these scripts or applications from the detection rule if they are verified as non-malicious.
* Frequent use of control.exe with specific command-line arguments by system administrators or IT personnel for legitimate system management tasks can be excluded by creating user-based exceptions for these roles.
* If certain security tools or monitoring software are known to trigger this rule due to their operational behavior, consider excluding these tools after confirming their legitimacy and necessity.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the suspicious control.exe process to stop any ongoing malicious execution.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious files or remnants.
* Review and clean up any unauthorized changes or files in the directories specified in the alert, such as AppData/Local or Users/Public, to ensure no persistence mechanisms remain.
* Restore any affected files or system settings from a known good backup to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are compromised.
* Implement additional monitoring and alerting for similar command-line anomalies to enhance detection and prevent recurrence of this threat.


## Rule query [_rule_query_245]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "control.exe" and
  process.command_line : (
    "*.jpg*", "*.png*",
    "*.gif*", "*.bmp*",
    "*.jpeg*", "*.TIFF*",
    "*.inf*", "*.cpl:*/*",
    "*../../..*",
    "*/AppData/Local/*",
    "*:\\Users\\Public\\*",
    "*\\AppData\\Local\\*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Control Panel
    * ID: T1218.002
    * Reference URL: [https://attack.mitre.org/techniques/T1218/002/](https://attack.mitre.org/techniques/T1218/002/)



