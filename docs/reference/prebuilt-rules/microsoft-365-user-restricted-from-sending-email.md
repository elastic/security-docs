---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-user-restricted-from-sending-email.html
---

# Microsoft 365 User Restricted from Sending Email [microsoft-365-user-restricted-from-sending-email]

Identifies when a user has been restricted from sending email due to exceeding sending limits of the service policies per the Security Compliance Center.

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

* [https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy](https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy)
* [https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference](https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_524]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 User Restricted from Sending Email**

Microsoft 365 enforces email sending limits to prevent abuse and ensure service integrity. Adversaries may exploit compromised accounts to send spam or phishing emails, triggering these limits. The detection rule monitors audit logs for successful restrictions by the Security Compliance Center, indicating potential misuse of valid accounts, aligning with MITRE ATT&CK’s Initial Access tactic.

**Possible investigation steps**

* Review the audit logs in Microsoft 365 to confirm the event details, focusing on entries with event.dataset:o365.audit and event.provider:SecurityComplianceCenter to ensure the restriction was logged correctly.
* Identify the user account that was restricted by examining the event.action:"User restricted from sending email" and event.outcome:success fields to understand which account triggered the alert.
* Investigate the recent email activity of the restricted user account to determine if there was any unusual or suspicious behavior, such as a high volume of outbound emails or patterns consistent with spam or phishing.
* Check for any recent changes in account permissions or configurations that might indicate unauthorized access or compromise, aligning with the MITRE ATT&CK technique T1078 for Valid Accounts.
* Assess whether there are any other related alerts or incidents involving the same user or similar patterns, which could indicate a broader security issue or coordinated attack.

**False positive analysis**

* High-volume legitimate email campaigns by marketing or communication teams can trigger sending limits. Coordinate with these teams to understand their schedules and create exceptions for known campaigns.
* Automated systems or applications using Microsoft 365 accounts for sending notifications or alerts may exceed limits. Identify these accounts and consider using service accounts with appropriate permissions and limits.
* Users with delegated access to multiple mailboxes might inadvertently trigger restrictions. Review and adjust permissions or create exceptions for these users if their activity is verified as legitimate.
* Temporary spikes in email activity due to business needs, such as end-of-quarter communications, can cause false positives. Monitor these periods and adjust thresholds or create temporary exceptions as needed.
* Misconfigured email clients or scripts that repeatedly attempt to send emails can appear as suspicious activity. Ensure proper configuration and monitor for any unusual patterns that may need exceptions.

**Response and remediation**

* Immediately disable the compromised user account to prevent further unauthorized email activity and potential spread of phishing or spam.
* Conduct a password reset for the affected account and enforce multi-factor authentication (MFA) to enhance security and prevent future unauthorized access.
* Review the audit logs for any additional suspicious activities associated with the compromised account, such as unusual login locations or times, and investigate any anomalies.
* Notify the affected user and relevant stakeholders about the incident, providing guidance on recognizing phishing attempts and securing their accounts.
* Escalate the incident to the security operations team for further analysis and to determine if other accounts or systems have been compromised.
* Implement additional email filtering rules to block similar phishing or spam patterns identified in the incident to prevent recurrence.
* Update and enhance detection rules and monitoring to quickly identify and respond to similar threats in the future, leveraging insights from the current incident.


## Setup [_setup_347]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_563]

```js
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



