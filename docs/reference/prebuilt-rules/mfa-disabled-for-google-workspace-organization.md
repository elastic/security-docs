---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/mfa-disabled-for-google-workspace-organization.html
---

# MFA Disabled for Google Workspace Organization [mfa-disabled-for-google-workspace-organization]

Detects when multi-factor authentication (MFA) is disabled for a Google Workspace organization. An adversary may attempt to modify a password policy in order to weaken an organization’s security controls.

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

## Investigation guide [_investigation_guide_486]

**Triage and analysis**

**Investigating MFA Disabled for Google Workspace Organization**

Multi-factor authentication (MFA) is a process in which users are prompted for an additional form of identification, such as a code on their cell phone or a fingerprint scan, during the sign-in process.

If you only use a password to authenticate a user, it leaves an insecure vector for attack. If the users’s password is weak or has been exposed elsewhere, an attacker could use it to gain access. Requiring a second form of authentication increases security because attackers cannot easily obtain or duplicate the additional authentication factor.

For more information about using MFA in Google Workspace, access the [official documentation](https://support.google.com/a/answer/175197).

This rule identifies when MFA enforcement is turned off in Google Workspace. This modification weakens account security and can lead to accounts and other assets being compromised.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user account during the past 48 hours.
* Contact the account and resource owners and confirm whether they are aware of this activity.
* Check if this operation was approved and performed according to the organization’s change management policy.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

**False positive analysis**

* While this activity can be done by administrators, all users must use MFA. The security team should address any potential benign true positive (B-TP), as this configuration can risk the user and domain.

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
* Reactivate the multi-factor authentication enforcement.
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


## Setup [_setup_312]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_523]

```js
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ENFORCE_STRONG_AUTHENTICATION or ALLOW_STRONG_AUTHENTICATION) and google_workspace.admin.new_value:false
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



