---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-veeam-credential-access-command.html
---

# Potential Veeam Credential Access Command [potential-veeam-credential-access-command]

Identifies commands that can access and decrypt Veeam credentials stored in MSSQL databases. Attackers can use Veeam Credentials to target backups as part of destructive operations such as Ransomware attacks.

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

**References**:

* [https://thedfirreport.com/2021/12/13/diavol-ransomware/](https://thedfirreport.com/2021/12/13/diavol-ransomware/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_785]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Veeam Credential Access Command**

Veeam credentials stored in MSSQL databases are crucial for managing backup operations. Attackers may exploit tools like `sqlcmd.exe` or PowerShell commands to access and decrypt these credentials, potentially leading to data breaches or ransomware attacks. The detection rule identifies suspicious command executions targeting Veeam credentials, focusing on specific processes and arguments, to alert analysts of potential credential access attempts.

**Possible investigation steps**

* Review the process execution details to confirm the presence of sqlcmd.exe or PowerShell commands like Invoke-Sqlcmd, focusing on the process.name and process.args fields.
* Examine the command line arguments for any references to [VeeamBackup].[dbo].[Credentials] to determine if there was an attempt to access or decrypt Veeam credentials.
* Check the user account associated with the process execution to assess if it is a legitimate user or potentially compromised.
* Investigate the source host for any signs of unauthorized access or suspicious activity, such as unusual login times or failed login attempts.
* Correlate the alert with other security events or logs from data sources like Microsoft Defender for Endpoint or Sysmon to identify any related malicious activities or patterns.
* Assess the risk and impact by determining if any Veeam credentials were successfully accessed or exfiltrated, and evaluate the potential for data breaches or ransomware attacks.

**False positive analysis**

* Routine database maintenance tasks may trigger the rule if they involve accessing Veeam credentials for legitimate purposes. To manage this, identify and document regular maintenance schedules and exclude these activities from triggering alerts.
* Automated scripts used for backup verification or testing might use similar commands. Review and whitelist these scripts by their process names or specific arguments to prevent unnecessary alerts.
* Internal security audits or compliance checks that involve credential access could be mistaken for malicious activity. Coordinate with audit teams to schedule these activities and create exceptions for known audit processes.
* Development or testing environments where Veeam credentials are accessed for non-production purposes can generate false positives. Implement environment-specific exclusions to differentiate between production and non-production activities.
* Legitimate use of PowerShell commands for database management by authorized personnel may be flagged. Maintain a list of authorized users and their typical command patterns to refine the detection rule and reduce false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the alert, such as `sqlcmd.exe` or PowerShell commands accessing Veeam credentials.
* Change all Veeam-related credentials stored in the MSSQL database to prevent further unauthorized access using compromised credentials.
* Conduct a thorough review of recent backup operations and logs to identify any unauthorized access or modifications.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring on systems storing Veeam credentials to detect similar suspicious activities in the future.
* Review and update access controls and permissions for MSSQL databases to ensure only authorized personnel have access to Veeam credentials.


## Rule query [_rule_query_833]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
    (process.name : "sqlcmd.exe" or ?process.pe.original_file_name : "sqlcmd.exe") or
    process.args : ("Invoke-Sqlcmd", "Invoke-SqlExecute", "Invoke-DbaQuery", "Invoke-SqlQuery")
  ) and
  process.args : "*[VeeamBackup].[dbo].[Credentials]*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



