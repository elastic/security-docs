---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-inbox-forwarding-rule-created.html
---

# Microsoft 365 Inbox Forwarding Rule Created [microsoft-365-inbox-forwarding-rule-created]

Identifies when a new Inbox forwarding rule is created in Microsoft 365. Inbox rules process messages in the Inbox based on conditions and take actions. In this case, the rules will forward the emails to a defined address. Attackers can abuse Inbox Rules to intercept and exfiltrate email data without making organization-wide configuration changes or having the corresponding privileges.

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

* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account?view=o365-worldwide)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide)
* [https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/Extractor%20Cheat%20Sheet.pdf](https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/Extractor%20Cheat%20Sheet.pdf)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Gary Blackwell
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_516]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Inbox Forwarding Rule Created**

Microsoft 365 allows users to create inbox rules to automate email management, such as forwarding messages to another address. While useful, attackers can exploit these rules to secretly redirect emails, facilitating data exfiltration. The detection rule monitors for the creation of such forwarding rules, focusing on successful events that specify forwarding parameters, thus identifying potential unauthorized email redirection activities.

**Possible investigation steps**

* Review the event details to identify the user account associated with the creation of the forwarding rule by examining the o365.audit.Parameters.
* Check the destination email address specified in the forwarding rule (ForwardTo, ForwardAsAttachmentTo, or RedirectTo) to determine if it is an external or suspicious address.
* Investigate the user’s recent activity logs in Microsoft 365 to identify any unusual or unauthorized actions, focusing on event.dataset:o365.audit and event.provider:Exchange.
* Verify if the user has a legitimate reason to create such a forwarding rule by consulting with their manager or reviewing their role and responsibilities.
* Assess if there have been any recent security incidents or alerts related to the user or the destination email address to identify potential compromise.
* Consider disabling the forwarding rule temporarily and notifying the user and IT security team if the rule appears suspicious or unauthorized.

**False positive analysis**

* Legitimate forwarding rules set by users for convenience or workflow purposes may trigger alerts. Review the context of the rule creation, such as the user and the destination address, to determine if it aligns with normal business operations.
* Automated systems or third-party applications that integrate with Microsoft 365 might create forwarding rules as part of their functionality. Identify these systems and consider excluding their associated accounts from the rule.
* Temporary forwarding rules set during user absence, such as vacations or leaves, can be mistaken for malicious activity. Implement a process to document and approve such rules, allowing for their exclusion from monitoring during the specified period.
* Internal forwarding to trusted domains or addresses within the organization might not pose a security risk. Establish a list of trusted internal addresses and configure exceptions for these in the detection rule.
* Frequent rule changes by specific users, such as IT administrators or support staff, may be part of their job responsibilities. Monitor these accounts separately and adjust the rule to reduce noise from expected behavior.

**Response and remediation**

* Immediately disable the forwarding rule by accessing the affected user’s mailbox settings in Microsoft 365 and removing any unauthorized forwarding rules.
* Conduct a thorough review of the affected user’s email account for any signs of compromise, such as unusual login activity or unauthorized changes to account settings.
* Reset the password for the affected user’s account and enforce multi-factor authentication (MFA) to prevent further unauthorized access.
* Notify the user and relevant IT security personnel about the incident, providing details of the unauthorized rule and any potential data exposure.
* Escalate the incident to the security operations team for further investigation and to determine if other accounts may have been targeted or compromised.
* Implement additional monitoring on the affected account and similar high-risk accounts to detect any further suspicious activity or rule changes.
* Review and update email security policies and configurations to prevent similar incidents, ensuring that forwarding rules are monitored and restricted as necessary.


## Setup [_setup_341]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_555]

```js
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:("New-InboxRule" or "Set-InboxRule") and
    (
        o365.audit.Parameters.ForwardTo:* or
        o365.audit.Parameters.ForwardAsAttachmentTo:* or
        o365.audit.Parameters.RedirectTo:*
    )
    and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Email Forwarding Rule
    * ID: T1114.003
    * Reference URL: [https://attack.mitre.org/techniques/T1114/003/](https://attack.mitre.org/techniques/T1114/003/)



