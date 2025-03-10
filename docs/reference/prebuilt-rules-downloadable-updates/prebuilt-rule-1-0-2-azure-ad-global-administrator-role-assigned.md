---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-azure-ad-global-administrator-role-assigned.html
---

# Azure AD Global Administrator Role Assigned [prebuilt-rule-1-0-2-azure-ad-global-administrator-role-assigned]

In Azure Active Directory (Azure AD), permissions to manage resources are assigned using roles. The Global Administrator is a role that enables users to have access to all administrative features in Azure AD and services that use Azure AD identities, such as the Microsoft 365 Defender portal, the Microsoft 365 compliance center, Exchange, SharePoint Online, and Skype for Business Online. Attackers can add users as Global Administrators to maintain access and manage all subscriptions and their settings and resources.

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

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1353]

## Config

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1567]

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

    * Name: Add Office 365 Global Administrator Role
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)



