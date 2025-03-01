---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-exchange-management-group-role-assignment.html
---

# Microsoft 365 Exchange Management Group Role Assignment [microsoft-365-exchange-management-group-role-assignment]

Identifies when a new role is assigned to a management group in Microsoft 365. An adversary may attempt to add a role in order to maintain persistence in an environment.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_510]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Management Group Role Assignment**

Microsoft 365 Exchange Management roles define permissions for managing Exchange environments. Adversaries may exploit this by assigning roles to unauthorized users, ensuring persistent access. The detection rule monitors successful role assignments within Exchange, flagging potential unauthorized changes that align with persistence tactics, thus aiding in identifying and mitigating unauthorized access attempts.

**Possible investigation steps**

* Review the event details to confirm the event.action is "New-ManagementRoleAssignment" and the event.outcome is "success" to ensure the alert is valid.
* Identify the user account associated with the role assignment by examining the event.dataset and event.provider fields, and verify if the account is authorized to make such changes.
* Check the history of role assignments for the identified user to determine if there are any patterns of unauthorized or suspicious activity.
* Investigate the specific management role that was assigned to understand its permissions and potential impact on the environment.
* Correlate this event with other recent activities from the same user or IP address to identify any additional suspicious behavior or anomalies.
* Consult with the relevant IT or security teams to verify if the role assignment was part of a legitimate administrative task or change request.

**False positive analysis**

* Routine administrative role assignments can trigger alerts. Regularly review and document legitimate role changes to differentiate them from unauthorized activities.
* Automated scripts or tools used for role management may cause false positives. Identify and whitelist these tools to prevent unnecessary alerts.
* Changes made during scheduled maintenance windows might be flagged. Establish a process to temporarily suppress alerts during these periods while ensuring post-maintenance reviews.
* Role assignments related to onboarding or offboarding processes can appear suspicious. Implement a verification step to confirm these changes align with HR records and expected activities.
* Frequent role changes by specific users with administrative privileges may not indicate malicious intent. Monitor these users' activities and establish a baseline to identify deviations from normal behavior.

**Response and remediation**

* Immediately revoke the newly assigned management role from the unauthorized user to prevent further unauthorized access or changes.
* Conduct a thorough review of recent activity logs for the affected account to identify any suspicious actions taken since the role assignment.
* Reset the credentials of the compromised account and enforce multi-factor authentication to enhance security.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring on the affected account and similar high-privilege accounts to detect any further unauthorized attempts.
* Review and update access control policies to ensure that only authorized personnel can assign management roles in Microsoft 365.
* Consider conducting a security awareness session for administrators to reinforce the importance of monitoring and managing role assignments securely.


## Setup [_setup_335]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_549]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-ManagementRoleAssignment" and event.outcome:success
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



