---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/group-policy-discovery-via-microsoft-gpresult-utility.html
---

# Group Policy Discovery via Microsoft GPResult Utility [group-policy-discovery-via-microsoft-gpresult-utility]

Detects the usage of gpresult.exe to query group policy objects. Attackers may query group policy objects during the reconnaissance phase after compromising a system to gain a better understanding of the active directory environment and possible methods to escalate privileges or move laterally.

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
* Tactic: Discovery
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_404]

**Triage and analysis**

**Investigating Group Policy Discovery via Microsoft GPResult Utility**

Group Policy is a Windows feature that allows administrators to manage and configure settings for users and computers in an Active Directory environment. The Microsoft GPResult utility (gpresult.exe) is a command-line tool used to query and display Group Policy Objects (GPOs) applied to a system. Attackers may abuse this utility to gain insights into the active directory environment and identify potential privilege escalation or lateral movement opportunities.

The detection rule *Group Policy Discovery via Microsoft GPResult Utility* is designed to identify the usage of gpresult.exe with specific arguments ("/z", "/v", "/r", "/x") that are commonly used by adversaries during the reconnaissance phase to perform group policy discovery.

**Possible investigation steps**

* Review the alert details to understand the context of the gpresult.exe usage, such as the user account, system, and time of execution.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.
* Inspect the host for suspicious or abnormal behavior in the alert timeframe.
* Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Investigate any abnormal behavior by the parent process, such as network connections, registry or file modifications, and any other spawned child processes.

**False positive analysis**

* Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Reimage the host operating system or restore the compromised files to clean versions.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_439]

```js
process where host.os.type == "windows" and event.type == "start" and
(process.name: "gpresult.exe" or ?process.pe.original_file_name == "gprslt.exe") and process.args: ("/z", "/v", "/r", "/x")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Group Policy Discovery
    * ID: T1615
    * Reference URL: [https://attack.mitre.org/techniques/T1615/](https://attack.mitre.org/techniques/T1615/)



