---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-cmd-execution-via-wmi.html
---

# Suspicious Cmd Execution via WMI [prebuilt-rule-8-17-4-suspicious-cmd-execution-via-wmi]

Identifies suspicious command execution (cmd) via Windows Management Instrumentation (WMI) on a remote host. This could be indicative of adversary lateral movement.

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

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper](https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper)
* [https://www.elastic.co/security-labs/operation-bleeding-bear](https://www.elastic.co/security-labs/operation-bleeding-bear)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 315

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4856]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Cmd Execution via WMI**

Windows Management Instrumentation (WMI) is a powerful framework for managing data and operations on Windows systems. Adversaries exploit WMI for lateral movement by executing commands remotely, often using cmd.exe. The detection rule identifies such activity by monitoring for cmd.exe processes initiated by WmiPrvSE.exe with specific arguments, indicating potential misuse for executing commands on remote hosts.

**Possible investigation steps**

* Review the process details to confirm the parent-child relationship between WmiPrvSE.exe and cmd.exe, ensuring that cmd.exe was indeed initiated by WmiPrvSE.exe.
* Examine the command-line arguments used by cmd.exe, specifically looking for the presence of "\\\\127.0.0.1\\*" and redirection operators like "2>&1" or "1>", to understand the nature of the command executed.
* Investigate the source and destination IP addresses involved in the WMI activity to determine if the remote host is legitimate or potentially compromised.
* Check for any related alerts or logs from the same host or user account around the same timeframe to identify any patterns or additional suspicious activities.
* Correlate the event with user activity logs to determine if the command execution aligns with expected user behavior or if it appears anomalous.
* Consult threat intelligence sources to see if the command or pattern matches known adversary techniques or campaigns.

**False positive analysis**

* Legitimate administrative tasks using WMI may trigger this rule. System administrators often use WMI for remote management, which can include executing scripts or commands. To handle this, identify and whitelist known administrative accounts or specific scripts that are regularly used for maintenance.
* Automated scripts or software that rely on WMI for legitimate operations might also cause false positives. Review and document these processes, then create exceptions for them in the detection rule to prevent unnecessary alerts.
* Security software or monitoring tools that utilize WMI for system checks can inadvertently match the rule’s criteria. Verify these tools and exclude their specific processes or arguments from the rule to reduce noise.
* Scheduled tasks or system updates that use WMI for execution might be flagged. Regularly review scheduled tasks and update the rule to exclude these known benign activities.
* Internal network monitoring or testing tools that simulate attacks for security assessments may trigger alerts. Ensure these activities are logged and excluded from the rule to avoid confusion during security evaluations.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement and potential data exfiltration. Disconnect it from the network while maintaining power to preserve volatile data for forensic analysis.
* Terminate any suspicious cmd.exe processes initiated by WmiPrvSE.exe to halt any ongoing malicious activities.
* Conduct a thorough review of the affected system’s WMI subscriptions and scripts to identify and remove any unauthorized or malicious entries.
* Reset credentials for any accounts that were used in the suspicious activity to prevent further unauthorized access.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Enhance monitoring and logging for WMI activities across the network to detect similar threats in the future, ensuring that logs are retained for an adequate period for forensic purposes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been compromised.


## Rule query [_rule_query_5811]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and
 process.args : "\\\\127.0.0.1\\*" and process.args : ("2>&1", "1>")
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

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)



