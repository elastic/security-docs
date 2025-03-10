---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-user-organizational-unit-changed.html
---

# Google Workspace User Organizational Unit Changed [google-workspace-user-organizational-unit-changed]

Users in Google Workspace are typically assigned a specific organizational unit that grants them permissions to certain services and roles that are inherited from this organizational unit. Adversaries may compromise a valid account and change which organizational account the user belongs to which then could allow them to inherit permissions to applications and resources inaccessible prior to.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/6328701?hl=en#](https://support.google.com/a/answer/6328701?hl=en#)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Configuration Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_402]

**Triage and analysis**

**Investigating Google Workspace User Organizational Unit Changed**

An organizational unit is a group that an administrator can create in the Google Admin console to apply settings to a specific set of users for Google Workspace. By default, all users are placed in the top-level (parent) organizational unit. Child organizational units inherit the settings from the parent but can be changed to fit the needs of the child organizational unit.

Permissions and privileges for users are often inherited from the organizational unit they are placed in. Therefore, if a user is changed to a separate organizational unit, they will inherit all privileges and permissions. User accounts may have unexpected privileges when switching organizational units that would allow a threat actor to gain a stronger foothold within the organization. The principle of least privileged (PoLP) should be followed when users are switched to different groups in Google Workspace.

This rule identifies when a user has been moved to a different organizational unit.

**Possible investigation steps**

* Identify the associated user accounts by reviewing `user.name` or `user.email` fields in the alert.
* The `user.target.email` field contains the user that had their assigned organizational unit switched.
* Identify the user’s previously assigned unit and new organizational unit by checking the `google_workspace.admin.org_unit.name` and `google_workspace.admin.new_value` fields.
* Identify Google Workspace applications whose settings were explicitly set for this organizational unit.
* Search for `event.action` is `CREATE_APPLICATION_SETTING` where `google_workspace.admin.org_unit.name` is the new organizational unit.
* After identifying the involved user, verify administrative privileges are scoped properly to allow changing user organizational units.
* Identify if the user account was recently created by searching for `event.action: CREATE_USER`.
* Add `user.email` with the target user account that recently had their organizational unit changed.
* Filter on `user.name` or `user.target.email` of the user who took this action and review the last 48 hours of activity for anything that may indicate a compromise.

**False positive analysis**

* After identifying the user account that changed another user’s organizational unit, verify the action was intentional.
* Verify whether the target user who received this update is expected to inherit privileges from the new organizational unit.
* Review potential maintenance notes or organizational changes. They might explain why a user’s organization was changed.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
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


## Setup [_setup_261]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_437]

```js
event.dataset:"google_workspace.admin" and event.type:change and event.category:iam
    and google_workspace.event.type:"USER_SETTINGS" and event.action:"MOVE_USER_TO_ORG_UNIT"
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



