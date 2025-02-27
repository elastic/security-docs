---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-exchange-dlp-policy-removed.html
---

# Microsoft 365 Exchange DLP Policy Removed [microsoft-365-exchange-dlp-policy-removed]

Identifies when a Data Loss Prevention (DLP) policy is removed in Microsoft 365. An adversary may remove a DLP policy to evade existing DLP monitoring.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-dlppolicy?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-dlppolicy?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/compliance/data-loss-prevention-policies?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/compliance/data-loss-prevention-policies?view=o365-worldwide)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_507]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange DLP Policy Removed**

Data Loss Prevention (DLP) in Microsoft 365 Exchange is crucial for safeguarding sensitive information by monitoring and controlling data transfers. Adversaries may exploit this by removing DLP policies to bypass data monitoring, facilitating unauthorized data exfiltration. The detection rule identifies such actions by analyzing audit logs for specific events indicating successful DLP policy removal, thus alerting security teams to potential defense evasion tactics.

**Possible investigation steps**

* Review the audit logs for the specific event.action "Remove-DlpPolicy" to identify the user account responsible for the action.
* Check the event.outcome field to confirm the success of the DLP policy removal and gather additional context from related logs.
* Investigate the user account’s recent activities in Microsoft 365 to identify any other suspicious actions or anomalies.
* Verify if the removed DLP policy was critical for protecting sensitive data and assess the potential impact of its removal.
* Contact the user or their manager to confirm if the DLP policy removal was authorized and legitimate.
* Examine any recent changes in permissions or roles for the user account to determine if they had the necessary privileges to remove the DLP policy.

**False positive analysis**

* Routine administrative changes to DLP policies by authorized personnel can trigger alerts. To manage this, maintain a list of authorized users and correlate their activities with policy changes to verify legitimacy.
* Scheduled updates or maintenance activities might involve temporary removal of DLP policies. Document these activities and create exceptions in the monitoring system for the duration of the maintenance window.
* Automated scripts or third-party tools used for policy management can inadvertently trigger false positives. Ensure these tools are properly documented and their actions are logged to differentiate between legitimate and suspicious activities.
* Changes in organizational policy or compliance requirements may necessitate the removal of certain DLP policies. Keep a record of such changes and adjust the monitoring rules to accommodate these legitimate actions.

**Response and remediation**

* Immediately isolate the affected Microsoft 365 account to prevent further unauthorized actions and data exfiltration.
* Review the audit logs to identify any additional unauthorized changes or suspicious activities associated with the account or related accounts.
* Restore the removed DLP policy from a backup or recreate it based on the organization’s standard configuration to re-enable data monitoring.
* Conduct a thorough investigation to determine the scope of data exposure and identify any data that may have been exfiltrated during the period the DLP policy was inactive.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional containment measures are necessary.
* Implement enhanced monitoring and alerting for similar events, focusing on unauthorized changes to security policies and configurations.
* Review and strengthen access controls and permissions for accounts with the ability to modify DLP policies to prevent unauthorized changes in the future.


## Setup [_setup_332]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_546]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-DlpPolicy" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)



