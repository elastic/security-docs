---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-powershell-script-with-veeam-credential-access-capabilities.html
---

# PowerShell Script with Veeam Credential Access Capabilities [prebuilt-rule-8-17-4-powershell-script-with-veeam-credential-access-capabilities]

Identifies PowerShell scripts that can access and decrypt Veeam credentials stored in MSSQL databases. Attackers can use Veeam Credentials to target backups as part of destructive operations such as Ransomware attacks.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html](https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.md)
* [https://www.crowdstrike.com/blog/anatomy-of-alpha-spider-ransomware/](https://www.crowdstrike.com/blog/anatomy-of-alpha-spider-ransomware/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4729]

**Triage and analysis**

[TBC: QUOTE]
**Investigating PowerShell Script with Veeam Credential Access Capabilities**

PowerShell, a powerful scripting language in Windows environments, can be exploited by attackers to access and decrypt sensitive credentials, such as those stored by Veeam in MSSQL databases. Adversaries may leverage this to compromise backup data, facilitating ransomware attacks. The detection rule identifies suspicious script activity by monitoring specific database interactions and decryption attempts, flagging potential credential access threats.

**Possible investigation steps**

* Review the PowerShell script block text associated with the alert to identify any references to "[dbo].[Credentials]" and "Veeam" or "VeeamBackup" to confirm potential credential access attempts.
* Check the event logs for the specific host where the alert was triggered to gather additional context about the process execution, including the user account involved and the script’s origin.
* Investigate any recent changes or access to the MSSQL database containing Veeam credentials to determine if there were unauthorized access attempts or modifications.
* Analyze the use of "ProtectedStorage]::GetLocalString" within the script to understand if it was used to decrypt or access sensitive information.
* Correlate the alert with other security events or logs from the same host or network segment to identify any related suspicious activities or patterns that could indicate a broader attack.

**False positive analysis**

* Routine administrative scripts that query MSSQL databases for maintenance purposes may trigger the rule. To manage this, identify and whitelist specific scripts or processes that are known to be safe and regularly executed by trusted administrators.
* Scheduled tasks or automated backup verification processes that access Veeam credentials for legitimate reasons can be mistaken for malicious activity. Exclude these tasks by specifying their unique identifiers or execution paths in the monitoring system.
* Security audits or compliance checks that involve accessing credential information for validation purposes might be flagged. Coordinate with the audit team to document these activities and create exceptions for their scripts.
* Development or testing environments where PowerShell scripts are used to simulate credential access for testing purposes can generate false positives. Implement environment-specific exclusions to prevent these from being flagged in production monitoring.
* Third-party monitoring tools that interact with Veeam credentials for health checks or performance monitoring may inadvertently trigger alerts. Work with the tool vendors to understand their access patterns and exclude them if they are verified as non-threatening.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious PowerShell processes identified by the detection rule to halt ongoing credential access attempts.
* Change all Veeam-related credentials and any other potentially compromised credentials stored in the MSSQL database to prevent further unauthorized access.
* Conduct a thorough review of backup integrity and ensure that no unauthorized modifications or deletions have occurred.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring for PowerShell activity and MSSQL database access to detect similar threats in the future.
* Review and update access controls and permissions for Veeam and MSSQL databases to ensure they follow the principle of least privilege.


## Setup [_setup_1517]

**Setup**

The *PowerShell Script Block Logging* logging policy must be enabled. Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

Steps to implement the logging policy via registry:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```


## Rule query [_rule_query_5684]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "[dbo].[Credentials]" and
      ("Veeam" or "VeeamBackup")
    ) or
    "ProtectedStorage]::GetLocalString"
  )
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



