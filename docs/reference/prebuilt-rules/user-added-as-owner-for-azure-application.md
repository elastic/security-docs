---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/user-added-as-owner-for-azure-application.html
---

# User Added as Owner for Azure Application [user-added-as-owner-for-azure-application]

Identifies when a user is added as an owner for an Azure application. An adversary may add a user account as an owner for an Azure application in order to grant additional permissions and modify the application’s configuration using another account.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

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

## Investigation guide [_investigation_guide_1172]

**Triage and analysis**

[TBC: QUOTE]
**Investigating User Added as Owner for Azure Application**

Azure applications often require specific permissions for functionality, managed by assigning user roles. An adversary might exploit this by adding themselves or a compromised account as an owner, gaining elevated privileges to alter configurations or access sensitive data. The detection rule monitors audit logs for successful operations where a user is added as an application owner, flagging potential unauthorized privilege escalations.

**Possible investigation steps**

* Review the Azure audit logs to confirm the operation by filtering for event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" with a successful outcome.
* Identify the user account that was added as an owner and the account that performed the operation to determine if they are legitimate or potentially compromised.
* Check the history of activities associated with both the added owner and the account that performed the operation to identify any suspicious behavior or patterns.
* Verify the application’s current configuration and permissions to assess any changes made after the new owner was added.
* Contact the legitimate owner or administrator of the Azure application to confirm whether the addition of the new owner was authorized.
* Investigate any recent changes in the organization’s user access policies or roles that might explain the addition of a new owner.

**False positive analysis**

* Routine administrative actions: Regular maintenance or updates by IT staff may involve adding users as application owners. To manage this, create a list of authorized personnel and exclude their actions from triggering alerts.
* Automated processes: Some applications may have automated scripts or services that add users as owners for operational purposes. Identify these processes and configure exceptions for their activities.
* Organizational changes: During mergers or restructuring, there may be legitimate reasons for adding multiple users as application owners. Temporarily adjust the rule to accommodate these changes and review the audit logs manually.
* Testing and development: In development environments, users may be added as owners for testing purposes. Exclude these environments from the rule or set up a separate monitoring policy with adjusted thresholds.

**Response and remediation**

* Immediately revoke the added user’s owner permissions from the Azure application to prevent further unauthorized access or configuration changes.
* Conduct a thorough review of recent activity logs for the affected application to identify any unauthorized changes or data access that may have occurred since the user was added as an owner.
* Reset credentials and enforce multi-factor authentication for the compromised or suspicious account to prevent further misuse.
* Notify the security team and relevant stakeholders about the incident for awareness and potential escalation if further investigation reveals broader compromise.
* Implement additional monitoring on the affected application and related accounts to detect any further unauthorized access attempts or privilege escalations.
* Review and update access control policies to ensure that only authorized personnel can modify application ownership, and consider implementing stricter approval processes for such changes.
* Document the incident, including actions taken and lessons learned, to improve response strategies and prevent recurrence.


## Setup [_setup_743]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_1195]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" and event.outcome:(Success or success)
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



