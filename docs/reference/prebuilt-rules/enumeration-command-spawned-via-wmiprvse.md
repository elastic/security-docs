---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/enumeration-command-spawned-via-wmiprvse.html
---

# Enumeration Command Spawned via WMIPrvSE [enumeration-command-spawned-via-wmiprvse]

Identifies native Windows host and network enumeration commands spawned by the Windows Management Instrumentation Provider Service (WMIPrvSE).

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

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

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

## Investigation guide [_investigation_guide_298]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Enumeration Command Spawned via WMIPrvSE**

Windows Management Instrumentation (WMI) is a powerful framework for managing data and operations on Windows systems. Adversaries exploit WMI to execute enumeration commands stealthily, leveraging the WMI Provider Service (WMIPrvSE) to gather system and network information. The detection rule identifies suspicious command executions initiated by WMIPrvSE, focusing on common enumeration tools while excluding benign use cases, thus highlighting potential malicious activity.

**Possible investigation steps**

* Review the process command line details to understand the specific enumeration command executed and its arguments, focusing on the process.command_line field.
* Investigate the parent process to confirm it is indeed WMIPrvSE by examining the process.parent.name field, ensuring the execution context aligns with potential misuse of WMI.
* Check the user context under which the process was executed to determine if it aligns with expected administrative activity or if it suggests unauthorized access.
* Correlate the event with other logs or alerts from the same host to identify any preceding or subsequent suspicious activities, such as lateral movement or privilege escalation attempts.
* Assess the network activity from the host around the time of the alert to identify any unusual outbound connections or data exfiltration attempts.
* Verify if the process execution is part of a known and legitimate administrative task or script by consulting with system administrators or reviewing change management records.

**False positive analysis**

* Routine administrative tasks using WMI may trigger the rule, such as network configuration checks or system diagnostics. To manage this, identify and exclude specific command patterns or arguments that are part of regular maintenance.
* Security tools like Tenable may use WMI for legitimate scans, which can be mistaken for malicious activity. Exclude processes with arguments related to known security tools, such as "tenable_mw_scan".
* Automated scripts or scheduled tasks that perform system enumeration for inventory or monitoring purposes can cause false positives. Review and whitelist these scripts by excluding their specific command lines or parent processes.
* Certain enterprise applications may use WMI for legitimate operations, such as querying system information. Identify these applications and create exceptions based on their process names or command line arguments.
* Regular use of network utilities by IT staff for troubleshooting can be flagged. Implement exclusions for known IT user accounts or specific command line patterns used during these activities.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified as being spawned by WMIPrvSE, especially those matching the enumeration tools listed in the detection query.
* Conduct a thorough review of recent WMI activity on the affected system to identify any additional unauthorized or suspicious commands executed.
* Reset credentials for any accounts that may have been compromised or used in the suspicious activity to prevent further unauthorized access.
* Restore the system from a known good backup if any malicious activity is confirmed and cannot be remediated through other means.
* Implement additional monitoring on the affected system and network to detect any recurrence of similar suspicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat has spread to other systems.


## Rule query [_rule_query_311]

```js
process where host.os.type == "windows" and event.type == "start" and process.command_line != null and
  process.name:
  (
    "arp.exe", "dsquery.exe", "dsget.exe", "gpresult.exe", "hostname.exe", "ipconfig.exe", "nbtstat.exe",
    "net.exe", "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "ping.exe", "qprocess.exe", "quser.exe",
    "qwinsta.exe", "reg.exe", "sc.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe", "whoami.exe"
  ) and
  process.parent.name:"wmiprvse.exe" and
  not (
    process.name : "sc.exe" and process.args : "RemoteRegistry" and process.args : "start=" and
    process.args : ("demand", "disabled")
  ) and
  not process.args : "tenable_mw_scan"
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

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Network Configuration Discovery
    * ID: T1016
    * Reference URL: [https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/)

* Sub-technique:

    * Name: Internet Connection Discovery
    * ID: T1016.001
    * Reference URL: [https://attack.mitre.org/techniques/T1016/001/](https://attack.mitre.org/techniques/T1016/001/)

* Technique:

    * Name: Remote System Discovery
    * ID: T1018
    * Reference URL: [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)



