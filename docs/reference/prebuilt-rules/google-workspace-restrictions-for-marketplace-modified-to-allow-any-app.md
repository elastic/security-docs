---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-restrictions-for-marketplace-modified-to-allow-any-app.html
---

# Google Workspace Restrictions for Marketplace Modified to Allow Any App [google-workspace-restrictions-for-marketplace-modified-to-allow-any-app]

Detects when the Google Marketplace restrictions are changed to allow any application for users in Google Workspace. Malicious APKs created by adversaries may be uploaded to the Google marketplace but not installed on devices managed within Google Workspace. Administrators should set restrictions to not allow any application from the marketplace for security reasons. Adversaries may enable any app to be installed and executed on mobile devices within a Google Workspace environment prior to distributing the malicious APK to the end user.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/6089179?hl=en](https://support.google.com/a/answer/6089179?hl=en)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_399]

**Triage and analysis**

**Investigating Google Workspace Restrictions for Marketplace Modified to Allow Any App**

Google Workspace Marketplace is an online store for free and paid web applications that work with Google Workspace services and third-party software. Listed applications are based on Google APIs or Google Apps Script and created by both Google and third-party developers.

Marketplace applications require access to specific Google Workspace resources. Applications can be installed by individual users, if they have permission, or can be installed for an entire Google Workspace domain by administrators. Consent screens typically display what permissions and privileges the application requires during installation. As a result, malicious Marketplace applications may require more permissions than necessary or have malicious intent.

Google clearly states that they are not responsible for any product on the Marketplace that originates from a source other than Google.

This rule identifies when the global allow-all setting is enabled for Google Workspace Marketplace applications.

**Possible investigation steps**

* Identify the associated user accounts by reviewing `user.name` or `user.email` fields in the alert.
* This rule relies on data from `google_workspace.admin`, thus indicating the associated user has administrative privileges to the Marketplace.
* Search for `event.action` is `ADD_APPLICATION` to identify applications installed after these changes were made.
* The `google_workspace.admin.application.name` field will help identify what applications were added.
* With the user account, review other potentially related events within the last 48 hours.
* Re-assess the permissions and reviews of the Marketplace applications to determine if they violate organizational policies or introduce unexpected risks.
* With access to the Google Workspace admin console, determine if the application was installed domain-wide or individually by visiting `Apps > Google Workspace Marketplace Apps`.

**False positive analysis**

* Identify the user account associated with this action and assess their administrative privileges with Google Workspace Marketplace.
* Google Workspace administrators may intentionally add an application from the marketplace based on organizational needs.
* Follow up with the user who added the application to ensure this was intended.
* Verify the application identified has been assessed thoroughly by an administrator.

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
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_258]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_434]

```js
event.dataset:"google_workspace.admin" and event.action:"CHANGE_APPLICATION_SETTING" and event.category:(iam or configuration)
    and google_workspace.event.type:"APPLICATION_SETTINGS" and google_workspace.admin.application.name:"Google Workspace Marketplace"
        and google_workspace.admin.setting.name:"Apps Access Setting Allowlist access"  and google_workspace.admin.new_value:"ALLOW_ALL"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



