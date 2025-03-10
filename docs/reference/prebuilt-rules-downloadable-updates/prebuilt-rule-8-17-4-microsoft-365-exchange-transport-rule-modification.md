---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-365-exchange-transport-rule-modification.html
---

# Microsoft 365 Exchange Transport Rule Modification [prebuilt-rule-8-17-4-microsoft-365-exchange-transport-rule-modification]

Identifies when a transport rule has been disabled or deleted in Microsoft 365. Mail flow rules (also known as transport rules) are used to identify and take action on messages that flow through your organization. An adversary or insider threat may modify a transport rule to exfiltrate data or evade defenses.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-transportrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/disable-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/disable-transportrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4225]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Transport Rule Modification**

Microsoft 365 Exchange transport rules manage email flow by setting conditions and actions for messages. Adversaries may exploit these rules to disable or delete them, facilitating data exfiltration or bypassing security measures. The detection rule monitors audit logs for successful execution of commands that alter these rules, signaling potential misuse and enabling timely investigation.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:o365.audit entries with event.provider:Exchange to confirm the occurrence of the "Remove-TransportRule" or "Disable-TransportRule" actions.
* Identify the user account associated with the event by examining the user information in the audit logs to determine if the action was performed by an authorized individual or a potential adversary.
* Check the event.category:web context to understand if the action was performed through a web interface, which might indicate a compromised account or unauthorized access.
* Investigate the event.outcome:success to ensure that the rule modification was indeed successful and not an attempted action.
* Correlate the timing of the rule modification with other security events or alerts to identify any concurrent suspicious activities that might suggest a broader attack or data exfiltration attempt.
* Assess the impact of the rule modification by reviewing the affected transport rules to determine if they were critical for security or compliance, and evaluate the potential risk to the organization.

**False positive analysis**

* Routine administrative changes to transport rules by IT staff can trigger alerts. To manage this, maintain a list of authorized personnel and their expected activities, and create exceptions for these users in the monitoring system.
* Scheduled maintenance or updates to transport rules may result in false positives. Document these activities and adjust the monitoring system to temporarily exclude these events during known maintenance windows.
* Automated scripts or third-party tools that manage transport rules might cause alerts. Identify these tools and their typical behavior, then configure the monitoring system to recognize and exclude these benign actions.
* Changes made as part of compliance audits or security assessments can be mistaken for malicious activity. Coordinate with audit teams to log these activities separately and adjust the monitoring system to account for these legitimate changes.

**Response and remediation**

* Immediately disable any compromised accounts identified in the audit logs to prevent further unauthorized modifications to transport rules.
* Revert any unauthorized changes to transport rules by restoring them to their previous configurations using backup data or logs.
* Conduct a thorough review of all transport rules to ensure no additional unauthorized modifications have been made, and confirm that all rules align with organizational security policies.
* Implement additional monitoring on the affected accounts and transport rules to detect any further suspicious activities or attempts to modify rules.
* Escalate the incident to the security operations team for a deeper investigation into potential data exfiltration activities and to assess the scope of the breach.
* Coordinate with legal and compliance teams to determine if any regulatory reporting is required due to potential data exfiltration.
* Enhance security measures by enabling multi-factor authentication (MFA) for all administrative accounts and reviewing access permissions to ensure the principle of least privilege is enforced.


## Setup [_setup_1086]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5223]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



