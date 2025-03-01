---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/o365-mailbox-audit-logging-bypass.html
---

# O365 Mailbox Audit Logging Bypass [o365-mailbox-audit-logging-bypass]

Detects the occurrence of mailbox audit bypass associations. The mailbox audit is responsible for logging specified mailbox events (like accessing a folder or a message or permanently deleting a message). However, actions taken by some authorized accounts, such as accounts used by third-party tools or accounts used for lawful monitoring, can create a large number of mailbox audit log entries and may not be of interest to your organization. Because of this, administrators can create bypass associations, allowing certain accounts to perform their tasks without being logged. Attackers can abuse this allowlist mechanism to conceal actions taken, as the mailbox audit will log no activity done by the account.

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

* [https://twitter.com/misconfig/status/1476144066807140355](https://twitter.com/misconfig/status/1476144066807140355)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Tactic: Initial Access
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_600]

**Triage and analysis**

[TBC: QUOTE]
**Investigating O365 Mailbox Audit Logging Bypass**

In Microsoft 365 environments, mailbox audit logging is crucial for tracking user activities like accessing or deleting emails. However, administrators can exempt certain accounts from logging to reduce noise, which attackers might exploit to hide their actions. The detection rule identifies successful attempts to create such exemptions, signaling potential misuse of this bypass mechanism.

**Possible investigation steps**

* Review the event logs for entries with event.dataset set to o365.audit and event.provider set to Exchange to confirm the presence of the Set-MailboxAuditBypassAssociation action.
* Identify the account associated with the event.action Set-MailboxAuditBypassAssociation and verify if it is a known and authorized account for creating audit bypass associations.
* Check the event.outcome field to ensure the action was successful and determine if there are any other related unsuccessful attempts that might indicate trial and error by an attacker.
* Investigate the history of the account involved in the bypass association to identify any unusual or suspicious activities, such as recent changes in permissions or unexpected login locations.
* Cross-reference the account with any known third-party tools or lawful monitoring accounts to determine if the bypass is legitimate or potentially malicious.
* Assess the risk and impact of the bypass by evaluating the types of activities that would no longer be logged for the account in question, considering the organization’s security policies and compliance requirements.

**False positive analysis**

* Authorized third-party tools may generate a high volume of mailbox audit log entries, leading to bypass associations being set. Review and document these tools to ensure they are legitimate and necessary for business operations.
* Accounts used for lawful monitoring might be exempted from logging to reduce noise. Verify that these accounts are properly documented and that their activities align with organizational policies.
* Regularly review the list of accounts with bypass associations to ensure that only necessary and approved accounts are included. Remove any accounts that no longer require exemptions.
* Implement a process for periodically auditing bypass associations to detect any unauthorized changes or additions, ensuring that only intended accounts are exempted from logging.
* Consider setting up alerts for any new bypass associations to quickly identify and investigate potential misuse or unauthorized changes.

**Response and remediation**

* Immediately isolate the account associated with the successful Set-MailboxAuditBypassAssociation event to prevent further unauthorized actions.
* Review and revoke any unauthorized mailbox audit bypass associations to ensure all relevant activities are logged.
* Conduct a thorough audit of recent activities performed by the affected account to identify any suspicious or malicious actions that may have been concealed.
* Reset credentials for the compromised account and any other accounts that may have been affected to prevent further unauthorized access.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring for similar bypass attempts to enhance detection capabilities and prevent recurrence.
* Consider escalating the incident to a higher security tier or external cybersecurity experts if the scope of the breach is extensive or if internal resources are insufficient to handle the threat.


## Setup [_setup_387]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_642]

```js
event.dataset:o365.audit and event.provider:Exchange and event.action:Set-MailboxAuditBypassAssociation and event.outcome:success
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

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



