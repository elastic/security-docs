---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-user-added-as-owner-for-azure-service-principal.html
---

# User Added as Owner for Azure Service Principal [prebuilt-rule-8-17-4-user-added-as-owner-for-azure-service-principal]

Identifies when a user is added as an owner for an Azure service principal. The service principal object defines what the application can do in the specific tenant, who can access the application, and what resources the app can access. A service principal object is created when an application is given permission to access resources in a tenant. An adversary may add a user account as an owner for a service principal and use that account in order to define what an application can do in the Azure AD tenant.

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

* [https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Configuration Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4113]

**Triage and analysis**

[TBC: QUOTE]
**Investigating User Added as Owner for Azure Service Principal**

Azure service principals are crucial for managing application permissions within a tenant, defining access and capabilities. Adversaries may exploit this by adding themselves as owners, gaining control over application permissions and access. The detection rule monitors audit logs for successful owner additions, flagging potential unauthorized changes to maintain security integrity.

**Possible investigation steps**

* Review the audit log entry to confirm the event dataset is *azure.auditlogs* and the operation name is "Add owner to service principal" with a successful outcome.
* Identify the user account that was added as an owner and gather information about this account, including recent activity and any associated alerts.
* Determine the service principal involved by reviewing its details, such as the application it is associated with and the permissions it holds.
* Check the history of changes to the service principal to identify any other recent modifications or suspicious activities.
* Investigate the context and necessity of the ownership change by contacting the user or team responsible for the service principal to verify if the change was authorized.
* Assess the potential impact of the ownership change on the tenant’s security posture, considering the permissions and access granted to the service principal.

**False positive analysis**

* Routine administrative changes may trigger alerts when legitimate IT staff add themselves or others as owners for maintenance purposes. To manage this, create exceptions for known administrative accounts that frequently perform these actions.
* Automated processes or scripts that manage service principal ownership as part of regular operations can cause false positives. Identify and document these processes, then exclude them from triggering alerts by using specific identifiers or tags.
* Organizational changes, such as team restructuring, might lead to multiple legitimate ownership changes. During these periods, temporarily adjust the rule sensitivity or create temporary exceptions for specific user groups involved in the transition.
* Third-party applications that require ownership changes for integration purposes can also trigger alerts. Verify these applications and whitelist their associated service principal changes to prevent unnecessary alerts.

**Response and remediation**

* Immediately revoke the added user’s ownership from the Azure service principal to prevent unauthorized access and control.
* Conduct a thorough review of the affected service principal’s permissions and access logs to identify any unauthorized changes or access attempts.
* Reset credentials and update any secrets or keys associated with the compromised service principal to mitigate potential misuse.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement conditional access policies to restrict who can add owners to service principals, ensuring only authorized personnel have this capability.
* Enhance monitoring and alerting for similar activities by increasing the sensitivity of alerts related to changes in service principal ownership.
* Document the incident and response actions taken to improve future incident response and refine security policies.


## Setup [_setup_1000]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5130]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to service principal" and event.outcome:(Success or success)
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



