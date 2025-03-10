---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-ad-global-administrator-role-assigned.html
---

# Azure AD Global Administrator Role Assigned [prebuilt-rule-8-17-4-azure-ad-global-administrator-role-assigned]

In Azure Active Directory (Azure AD), permissions to manage resources are assigned using roles. The Global Administrator is a role that enables users to have access to all administrative features in Azure AD and services that use Azure AD identities like the Microsoft 365 Defender portal, the Microsoft 365 compliance center, Exchange, SharePoint Online, and Skype for Business Online. Attackers can add users as Global Administrators to maintain access and manage all subscriptions and their settings and resources.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4110]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure AD Global Administrator Role Assigned**

Azure AD’s Global Administrator role grants comprehensive access to manage Azure AD and associated services. Adversaries may exploit this by assigning themselves or others to this role, ensuring persistent control over resources. The detection rule identifies such unauthorized assignments by monitoring specific audit logs for role changes, focusing on the addition of members to the Global Administrator role, thus helping to mitigate potential security breaches.

**Possible investigation steps**

* Review the Azure audit logs to identify the user account that performed the "Add member to role" operation, focusing on the specific event dataset and operation name.
* Verify the identity of the user added to the Global Administrator role by examining the modified properties in the audit logs, specifically the new_value field indicating "Global Administrator".
* Check the history of role assignments for the identified user to determine if this is a recurring pattern or a one-time event.
* Investigate the source IP address and location associated with the role assignment event to assess if it aligns with expected user behavior or if it indicates potential unauthorized access.
* Review any recent changes or activities performed by the newly assigned Global Administrator to identify any suspicious actions or configurations that may have been altered.
* Consult with the organization’s IT or security team to confirm if the role assignment was authorized and aligns with current administrative needs or projects.

**False positive analysis**

* Routine administrative tasks may trigger alerts when legitimate IT staff are assigned the Global Administrator role temporarily for maintenance or configuration purposes. To manage this, create exceptions for known IT personnel or scheduled maintenance windows.
* Automated scripts or third-party applications that require elevated permissions might be flagged if they are configured to add users to the Global Administrator role. Review and whitelist these scripts or applications if they are verified as safe and necessary for operations.
* Organizational changes, such as mergers or restructuring, can lead to legitimate role assignments that appear suspicious. Implement a review process to verify these changes and exclude them from triggering alerts if they align with documented organizational changes.
* Training or onboarding sessions for new IT staff might involve temporary assignment to the Global Administrator role. Establish a protocol to document and exclude these training-related assignments from detection alerts.

**Response and remediation**

* Immediately remove any unauthorized users from the Global Administrator role to prevent further unauthorized access and control over Azure AD resources.
* Conduct a thorough review of recent audit logs to identify any additional unauthorized changes or suspicious activities associated with the compromised account or role assignments.
* Reset the credentials of the affected accounts and enforce multi-factor authentication (MFA) to enhance security and prevent further unauthorized access.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Implement conditional access policies to restrict Global Administrator role assignments to specific, trusted locations or devices.
* Review and update role assignment policies to ensure that only a limited number of trusted personnel have the ability to assign Global Administrator roles.
* Enhance monitoring and alerting mechanisms to detect similar unauthorized role assignments in the future, ensuring timely response to potential threats.


## Setup [_setup_997]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5127]

```js
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
azure.auditlogs.operation_name:"Add member to role" and
azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value:"\"Global Administrator\""
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

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)



