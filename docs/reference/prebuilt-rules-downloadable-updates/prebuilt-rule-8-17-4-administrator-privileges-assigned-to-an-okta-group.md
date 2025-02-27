---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-administrator-privileges-assigned-to-an-okta-group.html
---

# Administrator Privileges Assigned to an Okta Group [prebuilt-rule-8-17-4-administrator-privileges-assigned-to-an-okta-group]

Detects when an administrator role is assigned to an Okta group. An adversary may attempt to assign administrator privileges to an Okta group in order to assign additional permissions to compromised user accounts and maintain access to their target organization.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm](https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4283]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Administrator Privileges Assigned to an Okta Group**

Okta is a widely used identity management service that facilitates secure user authentication and access control. Administrator privileges in Okta allow users to manage settings and permissions, making them a target for adversaries seeking persistent access. Malicious actors may exploit these privileges by assigning them to groups, thereby extending elevated access to compromised accounts. The detection rule monitors system events for privilege grants to groups, flagging potential unauthorized privilege escalations.

**Possible investigation steps**

* Review the event logs for entries with event.dataset:okta.system and event.action:group.privilege.grant to identify the specific group and administrator role assigned.
* Identify the user account that initiated the privilege grant action and verify if the account has a history of suspicious activity or if it has been compromised.
* Check the membership of the affected Okta group to determine which user accounts have gained elevated privileges and assess if any of these accounts are unauthorized or compromised.
* Investigate recent activities of the affected group members to identify any unusual or unauthorized actions that may indicate malicious intent.
* Review the organization’s change management records to confirm if the privilege assignment was part of an approved change request or if it was unauthorized.
* If unauthorized activity is confirmed, initiate incident response procedures to revoke the unauthorized privileges and secure the affected accounts.

**False positive analysis**

* Routine administrative tasks may trigger alerts when legitimate IT staff assign administrator roles to groups for maintenance or updates. To manage this, create exceptions for known IT personnel or scheduled maintenance windows.
* Organizational changes such as mergers or department restructuring might require temporary privilege escalations. Document these changes and adjust the detection rule to exclude these specific events during the transition period.
* Automated scripts or third-party integrations that manage group permissions could inadvertently trigger false positives. Identify these scripts and whitelist their actions within the monitoring system to prevent unnecessary alerts.
* Training or onboarding sessions where temporary admin access is granted to groups for demonstration purposes can cause alerts. Ensure these sessions are logged and recognized as non-threatening to avoid false positives.

**Response and remediation**

* Immediately revoke the administrator privileges assigned to the Okta group to prevent further unauthorized access or privilege escalation.
* Conduct a thorough review of recent group membership changes and privilege assignments in Okta to identify any other unauthorized modifications.
* Isolate and investigate any user accounts that were part of the affected group to determine if they have been compromised.
* Reset passwords and enforce multi-factor authentication (MFA) for all accounts that were part of the affected group to secure them against further unauthorized access.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and coordinated response efforts.
* Implement additional monitoring on the affected group and related user accounts to detect any further suspicious activities.
* Review and update access control policies to ensure that only necessary groups and users have administrative privileges, reducing the risk of similar incidents in the future.


## Setup [_setup_1140]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5281]

```js
event.dataset:okta.system and event.action:group.privilege.grant
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



