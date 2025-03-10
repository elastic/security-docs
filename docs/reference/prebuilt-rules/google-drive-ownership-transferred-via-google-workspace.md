---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-drive-ownership-transferred-via-google-workspace.html
---

# Google Drive Ownership Transferred via Google Workspace [google-drive-ownership-transferred-via-google-workspace]

Drive and Docs is a Google Workspace service that allows users to leverage Google Drive and Google Docs. Access to files is based on inherited permissions from the child organizational unit the user belongs to which is scoped by administrators. Typically if a user is removed, their files can be transferred to another user by the administrator. This service can also be abused by adversaries to transfer files to an adversary account for potential exfiltration.

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

* [https://support.google.com/a/answer/1247799?hl=en](https://support.google.com/a/answer/1247799?hl=en)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_387]

**Triage and analysis**

**Investigating Google Drive Ownership Transferred via Google Workspace**

Google Drive is a cloud storage service that allows users to store and access files. It is available to users with a Google Workspace account.

Google Workspace administrators consider users' roles and organizational units when assigning permissions to files or shared drives. Owners of sensitive files and folders can grant permissions to users who make internal or external access requests. Adversaries abuse this trust system by accessing Google Drive resources with improperly scoped permissions and shared settings. Distributing phishing emails is another common approach to sharing malicious Google Drive documents. With this approach, adversaries aim to inherit the recipient’s Google Workspace privileges when an external entity grants ownership.

This rule identifies when the ownership of a shared drive within a Google Workspace organization is transferred to another internal user.

**Possible investigation steps**

* From the admin console, review admin logs for involved user accounts. To find admin logs, go to `Security > Reporting > Audit and investigation > Admin log events`.
* Determine if involved user accounts are active. To view user activity, go to `Directory > Users`.
* Check if the involved user accounts were recently disabled, then re-enabled.
* Review involved user accounts for potentially misconfigured permissions or roles.
* Review the involved shared drive or files and related policies to determine if this action was expected and appropriate.
* If a shared drive, access requirements based on Organizational Units in `Apps > Google Workspace > Drive and Docs > Manage shared drives`.
* Triage potentially related alerts based on the users involved. To find alerts, go to `Security > Alerts`.

**False positive analysis**

* Transferring drives requires Google Workspace administration permissions related to Google Drive. Check if this action was planned/expected from the requester and is appropriately targeting the correct receiver.

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


## Setup [_setup_246]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_422]

```js
event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
  and event.category:"iam" and google_workspace.admin.application.name:Drive*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data Staged
    * ID: T1074
    * Reference URL: [https://attack.mitre.org/techniques/T1074/](https://attack.mitre.org/techniques/T1074/)

* Sub-technique:

    * Name: Remote Data Staging
    * ID: T1074.002
    * Reference URL: [https://attack.mitre.org/techniques/T1074/002/](https://attack.mitre.org/techniques/T1074/002/)



