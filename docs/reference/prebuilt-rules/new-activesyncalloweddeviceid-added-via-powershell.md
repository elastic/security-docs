---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/new-activesyncalloweddeviceid-added-via-powershell.html
---

# New ActiveSyncAllowedDeviceID Added via PowerShell [new-activesyncalloweddeviceid-added-via-powershell]

Identifies the use of the Exchange PowerShell cmdlet, Set-CASMailbox, to add a new ActiveSync allowed device. Adversaries may target user email to collect sensitive information.

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

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_589]

**Triage and analysis**

[TBC: QUOTE]
**Investigating New ActiveSyncAllowedDeviceID Added via PowerShell**

ActiveSync is a protocol enabling mobile devices to synchronize with Exchange mailboxes, crucial for accessing emails on-the-go. Adversaries may exploit the Exchange PowerShell cmdlet, Set-CASMailbox, to add unauthorized devices, gaining persistent access to sensitive email data. The detection rule identifies suspicious PowerShell activity by monitoring for specific command patterns, helping to flag potential unauthorized device additions and mitigate risks associated with account manipulation.

**Possible investigation steps**

* Review the alert details to identify the specific process name (e.g., powershell.exe, pwsh.exe, powershell_ise.exe) and the command line arguments used, focusing on the presence of "Set-CASMailbox" and "ActiveSyncAllowedDeviceIDs".
* Examine the user account associated with the process execution to determine if the account has a history of legitimate administrative actions or if it might be compromised.
* Check the device ID added to the ActiveSyncAllowedDeviceIDs list to verify if it is recognized and authorized for use within the organization.
* Investigate the source IP address and host from which the PowerShell command was executed to assess if it aligns with expected administrative activity or if it originates from an unusual or suspicious location.
* Review recent email access logs for the user account to identify any unusual patterns or access from unfamiliar devices that could indicate unauthorized access.
* Correlate this event with other security alerts or logs from data sources like Microsoft Defender for Endpoint or Sysmon to identify any related suspicious activities or patterns.

**False positive analysis**

* Legitimate administrative tasks may trigger the rule when IT staff use PowerShell to configure or update ActiveSync settings for users. To manage this, create exceptions for known administrative accounts or specific maintenance windows.
* Automated scripts for device management that include the Set-CASMailbox cmdlet can cause false positives. Review and whitelist these scripts if they are verified as part of routine operations.
* Third-party applications that integrate with Exchange and modify ActiveSync settings might be flagged. Identify and exclude these applications if they are trusted and necessary for business operations.
* Regular audits of device additions by authorized personnel can help distinguish between legitimate and suspicious activities, allowing for more accurate exception handling.
* Consider the context of the activity, such as the time of day and the user account involved, to refine detection rules and reduce false positives.

**Response and remediation**

* Immediately isolate the affected user account by disabling it to prevent further unauthorized access to the mailbox.
* Revoke the ActiveSync device access by removing the unauthorized device ID from the user’s mailbox settings using the Exchange PowerShell cmdlet.
* Conduct a thorough review of the affected user’s mailbox and account activity logs to identify any unauthorized access or data exfiltration attempts.
* Reset the password for the compromised user account and enforce multi-factor authentication (MFA) to enhance security.
* Notify the security team and relevant stakeholders about the incident for further investigation and potential escalation.
* Implement additional monitoring on the affected account and similar accounts for any unusual activity or further attempts to add unauthorized devices.
* Review and update the organization’s security policies and procedures related to mobile device access and PowerShell usage to prevent recurrence.


## Rule query [_rule_query_630]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Email Delegate Permissions
    * ID: T1098.002
    * Reference URL: [https://attack.mitre.org/techniques/T1098/002/](https://attack.mitre.org/techniques/T1098/002/)

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



