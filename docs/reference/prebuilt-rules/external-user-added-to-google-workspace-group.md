---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/external-user-added-to-google-workspace-group.html
---

# External User Added to Google Workspace Group [external-user-added-to-google-workspace-group]

Detects an external Google Workspace user account being added to an existing group. Adversaries may add external user accounts as a means to intercept shared files or emails with that specific group.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/33329](https://support.google.com/a/answer/33329)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_328]

**Triage and analysis**

**Investigating External User Added to Google Workspace Group**

Google Workspace groups allow organizations to assign specific users to a group that can share resources. Application specific roles can be manually set for each group, but if not inherit permissions from the top-level organizational unit.

Threat actors may use phishing techniques and container-bound scripts to add external Google accounts to an organization’s groups with editorial privileges. As a result, the user account is unable to manually access the organization’s resources, settings and files, but will receive anything shared to the group. As a result, confidential information could be leaked or perhaps documents shared with editorial privileges be weaponized for further intrusion.

This rule identifies when an external user account is added to an organization’s groups where the domain name of the target does not match the Google Workspace domain.

**Possible investigation steps**

* Identify user account(s) associated by reviewing `user.name` or `user.email` in the alert
* The `user.target.email` field contains the user added to the groups
* The `group.name` field contains the group the target user was added to
* Identify specific application settings given to the group which may indicate motive for the external user joining a particular group
* With the user identified, verify administrative privileges are scoped properly to add external users to the group
* Unauthorized actions may indicate the `user.email` account has been compromised or leveraged to add an external user
* To identify other users in this group, search for `event.action: "ADD_GROUP_MEMBER"`
* It is important to understand if external users with `@gmail.com` are expected to be added to this group based on historical references
* Review Gmail logs where emails were sent to and from the `group.name` value
* This may indicate potential internal spearphishing

**False positive analysis**

* With the user account whom added the new user, verify this action was intentional
* Verify that the target whom was added to the group is expected to have access to the organization’s resources and data
* If other members have been added to groups that are external, this may indicate historically that this action is expected

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
* Reactivate multi-factor authentication for the user.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security defaults [provided by Google](https://cloud.google.com/security-command-center/docs/how-to-investigate-threats).
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


## Setup [_setup_204]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_346]

```js
iam where event.dataset == "google_workspace.admin" and event.action == "ADD_GROUP_MEMBER" and
  not endsWith(user.target.email, user.target.group.domain)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)



