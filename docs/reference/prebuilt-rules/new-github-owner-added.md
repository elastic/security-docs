---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/new-github-owner-added.html
---

# New GitHub Owner Added [new-github-owner-added]

Detects when a new member is added to a GitHub organization as an owner. This role provides admin level privileges. Any new owner roles should be investigated to determine it’s validity. Unauthorized owner roles could indicate compromise within your organization and provide unlimited access to data and settings.

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

## Investigation guide [_investigation_guide_591]

**Triage and analysis**

[TBC: QUOTE]
**Investigating New GitHub Owner Added**

GitHub organizations allow collaborative management of repositories, where the *owner* role grants full administrative control. Adversaries may exploit this by adding unauthorized owners, gaining unrestricted access to sensitive data and settings. The detection rule monitors audit logs for new admin-level additions, flagging potential unauthorized access attempts for further investigation.

**Possible investigation steps**

* Review the GitHub audit logs to identify the specific user account that was added as an owner, focusing on the event.action "org.add_member" and github.permission "admin".
* Verify the identity and role of the newly added owner by cross-referencing with internal HR or user management systems to confirm if the addition was authorized.
* Check the activity history of the newly added owner account for any suspicious actions or changes made to repositories or settings since their addition.
* Contact the individual or team responsible for managing GitHub organization permissions to confirm if they were aware of and approved the new owner addition.
* Investigate any recent changes in the organization’s membership or access policies that might explain the addition of a new owner.
* Assess the potential impact of the new owner’s access by reviewing the repositories and sensitive data they now have administrative control over.

**False positive analysis**

* Legitimate organizational changes: New owners may be added during legitimate restructuring or team expansions. Regularly review and document organizational changes to differentiate between authorized and unauthorized additions.
* Automated processes: Some organizations use automated scripts or tools to manage GitHub permissions, which might trigger this rule. Identify and whitelist these processes to prevent unnecessary alerts.
* Temporary access requirements: Occasionally, temporary owner access might be granted for specific projects or tasks. Implement a process to track and review these temporary changes, ensuring they are reverted once the task is completed.
* Onboarding of new senior staff: When new senior staff members join, they might be added as owners. Establish a clear onboarding process that includes notifying the security team to avoid false positives.
* Cross-functional team collaborations: In some cases, cross-functional teams may require owner-level access for collaboration. Maintain a list of such collaborations and review them periodically to ensure they remain necessary and authorized.

**Response and remediation**

* Immediately revoke the admin privileges of the newly added GitHub owner to prevent further unauthorized access.
* Conduct a thorough review of recent changes and activities performed by the unauthorized owner to identify any potential data breaches or malicious actions.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and coordinated response efforts.
* Reset credentials and enforce multi-factor authentication for all existing GitHub organization owners to enhance security.
* Review and update access control policies to ensure that owner roles are granted only to verified and necessary personnel.
* Implement additional monitoring and alerting for any future changes to GitHub organization roles to detect similar threats promptly.
* If evidence of compromise is found, consider engaging with a digital forensics team to assess the full impact and scope of the breach.


## Rule query [_rule_query_632]

```js
iam where event.dataset == "github.audit" and event.action == "org.add_member" and github.permission == "admin"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Cloud Account
    * ID: T1136.003
    * Reference URL: [https://attack.mitre.org/techniques/T1136/003/](https://attack.mitre.org/techniques/T1136/003/)



