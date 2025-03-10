---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-admin-role-deletion.html
---

# Google Workspace Admin Role Deletion [google-workspace-admin-role-deletion]

Detects when a custom admin role is deleted. An adversary may delete a custom admin role in order to impact the permissions or capabilities of system administrators.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/2406043?hl=en](https://support.google.com/a/answer/2406043?hl=en)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Identity and Access Audit
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_391]

**Triage and analysis**

**Investigating Google Workspace Admin Role Deletion**

Google Workspace roles allow administrators to assign specific permissions to users or groups where the principle of least privilege (PoLP) is recommended. Admin roles in Google Workspace grant users access to the Google Admin console, where further domain-wide settings are accessible. Google Workspace contains prebuilt administrator roles for performing business functions related to users, groups, and services. Custom administrator roles can be created where prebuilt roles are not preferred.

Deleted administrator roles may render some user accounts inaccessible or cause operational failure where these roles are relied upon to perform daily administrative tasks. The deletion of roles may also hinder the response and remediation actions of administrators responding to security-related alerts and events. Without specific roles assigned, users will inherit the permissions and privileges of the root organizational unit.

This rule identifies when a Google Workspace administrative role is deleted within the Google Admin console.

**Possible investigation steps**

* Identify the associated user accounts by reviewing `user.name` or `user.email` fields in the alert.
* Identify the role deleted by reviewing `google_workspace.admin.role.name` in the alert.
* With the user identified, verify if he has administrative privileges to disable or delete administrative roles.
* To identify other users affected by this role removed, search for `event.action: ASSIGN_ROLE`.
* Add `google_workspace.admin.role.name` with the role deleted as an additional filter.
* Adjust the relative time accordingly to identify all users that were assigned this admin role.

**False positive analysis**

* After identifying the user account that disabled the admin role, verify the action was intentional.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Discuss with the user the affected users as a result of this action to mitigate operational discrepencies.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Assess the criticality of affected services and servers.
* Work with your IT team to identify and minimize the impact on users.
* Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
* Identify any regulatory or legal ramifications related to this activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords or delete API keys as needed to revoke the attacker’s access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://support.google.com/a/answer/7587183) by Google.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_250]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_426]

```js
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



