---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-password-policy-modified.html
---

# Google Workspace Password Policy Modified [google-workspace-password-policy-modified]

Detects when a Google Workspace password policy is modified. An adversary may attempt to modify a password policy in order to weaken an organization’s security controls.

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

* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_398]

**Triage and analysis**

**Investigating Google Workspace Password Policy Modified**

Google Workspace administrators manage password policies to enforce password requirements for an organization’s compliance needs. Administrators have the capability to set restrictions on password length, reset frequency, reuse capability, expiration, and much more. Google Workspace also allows multi-factor authentication (MFA) and 2-step verification (2SV) for authentication.

Threat actors might rely on weak password policies or restrictions to attempt credential access by using password stuffing or spraying techniques for cloud-based user accounts. Administrators might introduce increased risk to credential access from a third-party by weakening the password restrictions for an organization.

This rule detects when a Google Workspace password policy is modified to decrease password complexity or to adjust the reuse and reset frequency.

**Possible investigation steps**

* Identify associated user account(s) by reviewing the `user.name` or `source.user.email` fields in the alert.
* Identify the password setting that was created or adjusted by reviewing `google_workspace.admin.setting.name` field.
* Check if a password setting was enabled or disabled by reviewing the `google_workspace.admin.new_value` and `google_workspace.admin.old_value` fields.
* After identifying the involved user, verify administrative privileges are scoped properly to change.
* Filter `event.dataset` for `google_workspace.login` and aggregate by `user.name`, `event.action`.
* The `google_workspace.login.challenge_method` field can be used to identify the challenge method used for failed and successful logins.

**False positive analysis**

* After identifying the user account that updated the password policy, verify whether the action was intentional.
* Verify whether the user should have administrative privileges in Google Workspace to modify password policies.
* Review organizational units or groups the role may have been added to and ensure the new privileges align properly.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Consider resetting passwords for potentially affected users.
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
* Implement security best practices [outlined](https://support.google.com/a/answer/7587183) by Google.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators might observe lag times ranging from several minutes to 3 days between the event occurrence time and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_257]

The Google Workspace Fleet integration, the Filebeat module, or data that’s similarly structured is required for this rule.


## Rule query [_rule_query_433]

```js
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and
  event.action:(CHANGE_APPLICATION_SETTING or CREATE_APPLICATION_SETTING) and
  google_workspace.admin.setting.name:(
    "Password Management - Enforce strong password" or
    "Password Management - Password reset frequency" or
    "Password Management - Enable password reuse" or
    "Password Management - Enforce password policy at next login" or
    "Password Management - Minimum password length" or
    "Password Management - Maximum password length"
  )
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



