---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/google-workspace-2sv-policy-disabled.html
---

# Google Workspace 2SV Policy Disabled [google-workspace-2sv-policy-disabled]

Google Workspace admins may setup 2-step verification (2SV) to add an extra layer of security to user accounts by asking users to verify their identity when they use login credentials. Admins have the ability to enforce 2SV from the admin console as well as the methods acceptable for verification and enrollment period. 2SV requires enablement on admin accounts prior to it being enabled for users within organization units. Adversaries may disable 2SV to lower the security requirements to access a valid account.

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

* [https://support.google.com/a/answer/9176657?hl=en](https://support.google.com/a/answer/9176657?hl=en)
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

## Investigation guide [_investigation_guide_388]

**Triage and analysis**

**Investigating Google Workspace 2SV Policy Disabled**

Google Workspace administrators manage password policies to enforce password requirements for an organization’s compliance needs. Administrators have the capability to set restrictions on password length, reset frequencies, reuse capability, expiration, and much more. Google Workspace also allows multi-factor authentication (MFA) and 2-step verification (2SV) for authentication. 2SV allows users to verify their identity using security keys, Google prompt, authentication codes, text messages, and more.

2SV adds an extra authentication layer for Google Workspace users to verify their identity. If 2SV or MFA aren’t implemented, users only authenticate with their user name and password credentials. This authentication method has often been compromised and can be susceptible to credential access techniques when weak password policies are used.

This rule detects when a 2SV policy is disabled in Google Workspace.

**Possible investigation steps**

* Identify the associated user account(s) by reviewing `user.name` or `source.user.email` in the alert.
* Identify what password setting was created or adjusted by reviewing `google_workspace.admin.setting.name`.
* Review if a password setting was enabled or disabled by reviewing `google_workspace.admin.new_value` and `google_workspace.admin.old_value`.
* After identifying the involved user account, verify administrative privileges are scoped properly.
* Filter `event.dataset` for `google_workspace.login` and aggregate by `user.name`, `event.action`.
* The `google_workspace.login.challenge_method` field can be used to identify the challenge method that was used for failed and successful logins.

**False positive analysis**

* After finding the user account that updated the password policy, verify whether the action was intentional.
* Verify whether the user should have Google Workspace administrative privileges that allow them to modify password policies.
* Review organizational units or groups the role may have been added to and ensure its privileges are properly aligned.

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


## Setup [_setup_247]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_423]

```js
event.dataset:"google_workspace.login" and event.action:"2sv_disable"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



