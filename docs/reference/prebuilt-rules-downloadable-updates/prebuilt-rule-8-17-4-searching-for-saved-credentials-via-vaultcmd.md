---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-searching-for-saved-credentials-via-vaultcmd.html
---

# Searching for Saved Credentials via VaultCmd [prebuilt-rule-8-17-4-searching-for-saved-credentials-via-vaultcmd]

Windows Credential Manager allows you to create, view, or delete saved credentials for signing into websites, connected applications, and networks. An adversary may abuse this to list or dump credentials stored in the Credential Manager for saved usernames and passwords. This may also be performed in preparation of lateral movement.

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

* [https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)
* [https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/](https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4733]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Searching for Saved Credentials via VaultCmd**

Windows Credential Manager stores credentials for websites, applications, and networks. Adversaries exploit this by using VaultCmd to list or extract these credentials, aiding in lateral movement. The detection rule identifies such abuse by monitoring the execution of VaultCmd with specific arguments, flagging potential credential access attempts. This helps in early detection of unauthorized credential access activities.

**Possible investigation steps**

* Review the process execution details to confirm the presence of vaultcmd.exe with the /list* argument, as this indicates an attempt to list saved credentials.
* Check the user account associated with the process execution to determine if the activity aligns with expected behavior for that user or if it appears suspicious.
* Investigate the parent process of vaultcmd.exe to understand how it was initiated and whether it was triggered by a legitimate application or script.
* Examine recent login activity and network connections from the host to identify any signs of lateral movement or unauthorized access attempts.
* Correlate this event with other security alerts or logs from the same host or user to identify potential patterns of malicious behavior.
* Review endpoint security logs from tools like Microsoft Defender for Endpoint or Crowdstrike for additional context or corroborating evidence of credential access attempts.

**False positive analysis**

* Routine administrative tasks using VaultCmd for legitimate credential management can trigger alerts. To manage this, create exceptions for known administrative accounts or scheduled tasks that regularly use VaultCmd with the /list argument.
* Security software or system management tools that perform regular audits of stored credentials might also cause false positives. Identify these tools and exclude their processes from triggering the rule.
* Automated scripts or backup processes that access Credential Manager for legitimate purposes may be flagged. Review these scripts and whitelist them if they are verified as non-threatening.
* User-initiated credential management activities, such as listing credentials for personal use, can be mistaken for malicious behavior. Educate users on the implications of using VaultCmd and consider excluding specific user accounts if necessary.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement and further credential access.
* Terminate any suspicious processes associated with VaultCmd.exe to halt unauthorized credential dumping activities.
* Conduct a thorough review of the affected system’s event logs and process execution history to identify any additional malicious activities or compromised accounts.
* Reset passwords for any accounts that may have been exposed or accessed through the Credential Manager to mitigate unauthorized access.
* Implement enhanced monitoring on the affected system and similar endpoints for any further attempts to use VaultCmd.exe or other credential dumping tools.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the scope of the breach.
* Review and update endpoint protection configurations to ensure that similar threats are detected and blocked in the future, leveraging threat intelligence and MITRE ATT&CK framework insights.


## Rule query [_rule_query_5688]

```js
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
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

* Sub-technique:

    * Name: Windows Credential Manager
    * ID: T1555.004
    * Reference URL: [https://attack.mitre.org/techniques/T1555/004/](https://attack.mitre.org/techniques/T1555/004/)



