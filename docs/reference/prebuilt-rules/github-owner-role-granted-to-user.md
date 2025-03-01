---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/github-owner-role-granted-to-user.html
---

# GitHub Owner Role Granted To User [github-owner-role-granted-to-user]

This rule detects when a member is granted the organization owner role of a GitHub organization. This role provides admin level privileges. Any new owner role should be investigated to determine its validity. Unauthorized owner roles could indicate compromise within your organization and provide unlimited access to data and settings.

**Rule type**: eql

**Rule indices**:

* logs-github.audit-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Use Case: UEBA
* Tactic: Persistence
* Data Source: Github
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_383]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GitHub Owner Role Granted To User**

In GitHub organizations, the owner role grants comprehensive administrative privileges, enabling full control over repositories, settings, and data. Adversaries may exploit this by elevating privileges to maintain persistence or exfiltrate data. The detection rule monitors audit logs for changes in member roles to *admin*, signaling potential unauthorized access or privilege escalation attempts, thus aiding in early threat identification.

**Possible investigation steps**

* Review the audit logs for the specific event where the member’s role was changed to *admin* to identify the user who made the change and the user who received the new role.
* Verify the legitimacy of the role change by contacting the user who was granted the owner role and the user who performed the action to confirm if the change was authorized.
* Check the organization’s recent activity logs for any unusual or suspicious actions performed by the user who was granted the owner role, such as changes to repository settings or data access.
* Investigate any recent changes in the organization’s membership or permissions that could indicate a broader compromise or unauthorized access.
* Assess the potential impact of the role change by identifying sensitive repositories or data that the new owner role could access, and determine if any data exfiltration or unauthorized changes have occurred.

**False positive analysis**

* Role changes due to organizational restructuring or legitimate promotions can trigger alerts. Regularly update the list of expected role changes to minimize unnecessary alerts.
* Automated scripts or integrations that manage user roles might inadvertently trigger the rule. Identify and whitelist these scripts to prevent false positives.
* Temporary role assignments for project-specific tasks can be mistaken for unauthorized access. Implement a process to document and pre-approve such temporary changes.
* Changes made by trusted administrators during routine audits or maintenance may be flagged. Maintain a log of scheduled maintenance activities to cross-reference with alerts.
* Onboarding processes that involve granting admin roles to new employees can generate alerts. Ensure that onboarding procedures are documented and known exceptions are configured in the detection system.

**Response and remediation**

* Immediately revoke the owner role from the user account identified in the alert to prevent further unauthorized access or changes.
* Conduct a thorough review of recent activities performed by the user with the elevated privileges to identify any unauthorized changes or data access.
* Reset the credentials and enforce multi-factor authentication for the affected user account to secure it against further compromise.
* Notify the security team and relevant stakeholders about the potential breach and involve them in the investigation and remediation process.
* Review and update access control policies to ensure that owner roles are granted only through a formal approval process and are regularly audited.
* Implement additional monitoring and alerting for changes to high-privilege roles within the organization to detect similar threats in the future.


## Rule query [_rule_query_415]

```js
iam where event.dataset == "github.audit" and event.action == "org.update_member" and github.permission == "admin"
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



