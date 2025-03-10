---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-object-copied-to-external-drive-with-app-consent.html
---

# Google Workspace Object Copied to External Drive with App Consent [google-workspace-object-copied-to-external-drive-with-app-consent]

Detects when a user copies a Google spreadsheet, form, document or script from an external drive. Sequence logic has been added to also detect when a user grants a custom Google application permission via OAuth shortly after. An adversary may send a phishing email to the victim with a Drive object link where "copy" is included in the URI, thus copying the object to the victim’s drive. If a container-bound script exists within the object, execution will require permission access via OAuth in which the user has to accept.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)
* [https://developers.google.com/apps-script/guides/bound](https://developers.google.com/apps-script/guides/bound)
* [https://support.google.com/a/users/answer/13004165#share_make_a_copy_links](https://support.google.com/a/users/answer/13004165#share_make_a_copy_links)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_397]

**Triage and analysis**

**Investigating Google Workspace Object Copied to External Drive with App Consent**

Google Workspace users can share access to Drive objects such as documents, sheets, and forms via email delivery or a shared link. Shared link URIs have parameters like `view` or `edit` to indicate the recipient’s permissions. The `copy` parameter allows the recipient to copy the object to their own Drive, which grants the object with the same privileges as the recipient. Specific objects in Google Drive allow container-bound scripts that run on Google’s Apps Script platform. Container-bound scripts can contain malicious code that executes with the recipient’s privileges if in their Drive.

This rule aims to detect when a user copies an external Drive object to their Drive storage and then grants permissions to a custom application via OAuth prompt.

**Possible investigation steps**

* Identify user account(s) associated by reviewing `user.name` or `source.user.email` in the alert.
* Identify the name of the file copied by reviewing `file.name` as well as the `file.id` for triaging.
* Identify the file type by reviewing `google_workspace.drive.file.type`.
* With the information gathered so far, query across data for the file metadata to determine if this activity is isolated or widespread.
* Within the OAuth token event, identify the application name by reviewing `google_workspace.token.app_name`.
* Review the application ID as well from `google_workspace.token.client.id`.
* This metadata can be used to report the malicious application to Google for permanent blacklisting.
* Identify the permissions granted to the application by the user by reviewing `google_workspace.token.scope.data.scope_name`.
* This information will help pivot and triage into what services may have been affected.
* If a container-bound script was attached to the copied object, it will also exist in the user’s drive.
* This object should be removed from all users affected and investigated for a better understanding of the malicious code.

**False positive analysis**

* Communicate with the affected user to identify if these actions were intentional
* If a container-bound script exists, review code to identify if it is benign or malicious

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
* Resetting passwords will revoke OAuth tokens which could have been stolen.
* Reactivate multi-factor authentication for the user.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security defaults [provided by Google](https://cloud.google.com/security-command-center/docs/how-to-investigate-threats).
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

**Setup**

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_256]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_432]

```js
sequence by source.user.email with maxspan=3m
[file where event.dataset == "google_workspace.drive" and event.action == "copy" and

    /* Should only match if the object lives in a Drive that is external to the user's GWS organization */
    google_workspace.drive.owner_is_team_drive == "false" and google_workspace.drive.copy_type == "external" and

    /* Google Script, Forms, Sheets and Document can have container-bound scripts */
    google_workspace.drive.file.type: ("script", "form", "spreadsheet", "document")]

[any where event.dataset == "google_workspace.token" and event.action == "authorize" and

    /* Ensures application ID references custom app in Google Workspace and not GCP */
    google_workspace.token.client.id : "*apps.googleusercontent.com"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)



