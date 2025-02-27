---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-administrator-role-assigned-to-an-okta-user.html
---

# Administrator Role Assigned to an Okta User [prebuilt-rule-8-17-4-administrator-role-assigned-to-an-okta-user]

Identifies when an administrator role is assigned to an Okta user. An adversary may attempt to assign an administrator role to an Okta user in order to assign additional permissions to a user account and maintain access to their target’s environment.

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
* [https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know](https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know)

**Tags**:

* Data Source: Okta
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4284]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Administrator Role Assigned to an Okta User**

Okta is a widely used identity management service that facilitates secure user authentication and access control. In environments using Okta, assigning an administrator role grants elevated permissions, which can be exploited by adversaries to maintain unauthorized access. The detection rule monitors system events for privilege grants, flagging suspicious role assignments to mitigate potential abuse.

**Possible investigation steps**

* Review the event details to confirm the presence of the event.dataset:okta.system and event.action:user.account.privilege.grant fields, ensuring the alert is triggered by the correct conditions.
* Identify the user account that was assigned the administrator role and gather information about their recent activities and login history to assess any unusual behavior.
* Check the timestamp of the role assignment event to determine if it coincides with any other suspicious activities or known incidents.
* Investigate the source IP address and location associated with the role assignment event to verify if it aligns with the user’s typical access patterns.
* Review the change history for the affected user account to identify any other recent modifications or privilege escalations that may indicate malicious intent.
* Consult with the user or their manager to verify if the role assignment was authorized and legitimate, documenting any discrepancies or unauthorized actions.

**False positive analysis**

* Routine administrative tasks may trigger the rule when legitimate IT staff assign administrator roles for maintenance or onboarding purposes. To manage this, create exceptions for known IT personnel or scheduled maintenance windows.
* Automated scripts or integrations that require elevated permissions might cause false positives. Identify these scripts and whitelist their associated accounts to prevent unnecessary alerts.
* Organizational changes such as mergers or department restructuring can lead to multiple legitimate role assignments. During these periods, temporarily adjust the rule sensitivity or increase monitoring to differentiate between expected and suspicious activities.
* Training or testing environments where roles are frequently assigned for simulation purposes can generate false positives. Exclude these environments from the rule or set up a separate monitoring profile for them.

**Response and remediation**

* Immediately revoke the administrator role from the affected Okta user account to prevent further unauthorized access or privilege escalation.
* Conduct a thorough review of recent activity logs for the affected user account to identify any unauthorized actions or changes made while the elevated privileges were active.
* Reset the password and enforce multi-factor authentication (MFA) for the affected user account to secure it against potential compromise.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized role assignment and any identified malicious activities.
* Implement additional monitoring for the affected user account and similar accounts to detect any further suspicious activities or attempts to reassign elevated privileges.
* Review and update access control policies to ensure that administrator role assignments require additional verification or approval processes to prevent unauthorized changes.
* If evidence of broader compromise is found, initiate a full security incident response process, including forensic analysis and potential involvement of external cybersecurity experts.


## Setup [_setup_1141]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5282]

```js
event.dataset:okta.system and event.action:user.account.privilege.grant
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



