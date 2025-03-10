---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-exchange-transport-rule-creation.html
---

# Microsoft 365 Exchange Transport Rule Creation [microsoft-365-exchange-transport-rule-creation]

Identifies a transport rule creation in Microsoft 365. As a best practice, Exchange Online mail transport rules should not be set to forward email to domains outside of your organization. An adversary may create transport rules to exfiltrate data.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-transportrule?view=exchange-ps)
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

## Investigation guide [_investigation_guide_513]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Transport Rule Creation**

Microsoft 365 Exchange transport rules automate email handling, applying actions like forwarding or blocking based on conditions. While beneficial for managing communications, adversaries can exploit these rules to redirect emails externally, facilitating data exfiltration. The detection rule monitors successful creation of new transport rules, flagging potential misuse by identifying specific actions and outcomes in audit logs.

**Possible investigation steps**

* Review the audit logs for the event.dataset:o365.audit to identify the user account responsible for creating the new transport rule.
* Examine the event.provider:Exchange and event.category:web fields to confirm the context and source of the rule creation.
* Investigate the event.action:"New-TransportRule" to understand the specific conditions and actions defined in the newly created transport rule.
* Check the event.outcome:success to ensure the rule creation was completed successfully and assess if it aligns with expected administrative activities.
* Analyze the transport rule settings to determine if it includes actions that forward emails to external domains, which could indicate potential data exfiltration.
* Correlate the findings with other security events or alerts to identify any patterns or anomalies that might suggest malicious intent.

**False positive analysis**

* Routine administrative tasks may trigger alerts when IT staff create or modify transport rules for legitimate purposes. To manage this, establish a baseline of expected rule creation activities and exclude these from alerts.
* Automated systems or third-party applications that integrate with Microsoft 365 might create transport rules as part of their normal operation. Identify these systems and create exceptions for their known actions.
* Changes in organizational policies or email handling procedures can lead to legitimate rule creations. Document these changes and update the monitoring system to recognize them as non-threatening.
* Regular audits or compliance checks might involve creating temporary transport rules. Coordinate with audit teams to schedule these activities and temporarily adjust alert thresholds or exclusions during these periods.

**Response and remediation**

* Immediately disable the newly created transport rule to prevent further unauthorized email forwarding or data exfiltration.
* Conduct a thorough review of the audit logs to identify any other suspicious transport rules or related activities that may indicate a broader compromise.
* Isolate the affected user accounts or systems associated with the creation of the transport rule to prevent further unauthorized access or actions.
* Reset passwords and enforce multi-factor authentication for the affected accounts to secure access and prevent recurrence.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Escalate the incident to the incident response team if there is evidence of a broader compromise or if sensitive data has been exfiltrated.
* Implement enhanced monitoring and alerting for transport rule changes to detect and respond to similar threats more effectively in the future.


## Setup [_setup_338]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_552]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
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



