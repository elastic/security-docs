---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-external-guest-user-invitation.html
---

# Azure External Guest User Invitation [prebuilt-rule-8-17-4-azure-external-guest-user-invitation]

Identifies an invitation to an external user in Azure Active Directory (AD). Azure AD is extended to include collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account. Unless there is a business need to provision guest access, it is best practice avoid creating guest users. Guest users could potentially be overlooked indefinitely leading to a potential vulnerability.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/governance/policy/samples/cis-azure-1-1-0](https://docs.microsoft.com/en-us/azure/governance/policy/samples/cis-azure-1-1-0)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4105]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure External Guest User Invitation**

Azure Active Directory (AD) facilitates collaboration by allowing external users to be invited as guest users, enhancing flexibility in cloud environments. However, adversaries may exploit this feature to gain unauthorized access, posing security risks. The detection rule monitors audit logs for successful external user invitations, flagging potential misuse by identifying unusual or unnecessary guest account creations.

**Possible investigation steps**

* Review the audit logs to confirm the details of the invitation event, focusing on the operation name "Invite external user" and ensuring the event outcome is marked as Success.
* Identify the inviter by examining the properties of the audit log entry, such as the initiator’s user ID or email, to determine if the invitation was expected or authorized.
* Check the display name and other attributes of the invited guest user to assess if they align with known business needs or if they appear suspicious or unnecessary.
* Investigate the inviter’s recent activity in Azure AD to identify any unusual patterns or deviations from their typical behavior that might indicate compromised credentials.
* Consult with relevant business units or stakeholders to verify if there was a legitimate business requirement for the guest user invitation and if it aligns with current projects or collaborations.
* Review the access permissions granted to the guest user to ensure they are limited to the minimum necessary for their role and do not expose sensitive resources.

**False positive analysis**

* Invitations for legitimate business partners or vendors may trigger alerts. Regularly review and whitelist known partners to prevent unnecessary alerts.
* Internal users with dual roles or responsibilities that require external access might be flagged. Maintain a list of such users and update it periodically to exclude them from alerts.
* Automated systems or applications that require guest access for integration purposes can cause false positives. Identify these systems and configure exceptions in the monitoring rules.
* Temporary projects or collaborations often involve inviting external users. Document these projects and set expiration dates for guest access to minimize false positives.
* Frequent invitations from specific departments, such as HR or Marketing, for events or collaborations can be common. Establish a process to verify and approve these invitations to reduce false alerts.

**Response and remediation**

* Immediately disable the guest user account identified in the alert to prevent any unauthorized access or activities.
* Review the audit logs to determine the source and context of the invitation, identifying the user or system that initiated the guest invitation.
* Notify the security team and relevant stakeholders about the unauthorized guest invitation for further investigation and potential escalation.
* Conduct a security assessment of the affected Azure AD environment to identify any other unauthorized guest accounts or suspicious activities.
* Implement conditional access policies to restrict guest user invitations to authorized personnel only, reducing the risk of future unauthorized invitations.
* Enhance monitoring and alerting for guest user invitations by integrating with a Security Information and Event Management (SIEM) system to ensure timely detection and response.
* Review and update the organization’s Azure AD guest user policies to ensure they align with security best practices and business needs, minimizing unnecessary guest access.


## Setup [_setup_992]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5122]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
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

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



