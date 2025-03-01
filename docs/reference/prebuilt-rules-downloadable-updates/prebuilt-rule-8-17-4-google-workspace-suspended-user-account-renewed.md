---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-google-workspace-suspended-user-account-renewed.html
---

# Google Workspace Suspended User Account Renewed [prebuilt-rule-8-17-4-google-workspace-suspended-user-account-renewed]

Detects when a previously suspended user’s account is renewed in Google Workspace. An adversary may renew a suspended user account to maintain access to the Google Workspace organization with a valid account.

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

* [https://support.google.com/a/answer/1110339](https://support.google.com/a/answer/1110339)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4192]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Google Workspace Suspended User Account Renewed**

Google Workspace manages user identities and access, crucial for organizational security. Adversaries may exploit the renewal of suspended accounts to regain unauthorized access, bypassing security measures. The detection rule identifies such events by monitoring specific administrative actions, helping analysts spot potential misuse and maintain secure access controls.

**Possible investigation steps**

* Review the event logs for the specific action `UNSUSPEND_USER` to identify the user account that was renewed and gather details about the timing and context of the action.
* Check the identity of the administrator or service account that performed the `UNSUSPEND_USER` action to determine if the action was authorized or if there are signs of account compromise.
* Investigate the history of the suspended user account to understand why it was initially suspended and assess any potential risks associated with its renewal.
* Examine recent activity logs for the renewed user account to identify any suspicious behavior or unauthorized access attempts following the account’s reactivation.
* Cross-reference the event with other security alerts or incidents to determine if the renewal is part of a broader pattern of suspicious activity within the organization.

**False positive analysis**

* Routine administrative actions may trigger the rule when IT staff unsuspend accounts for legitimate reasons, such as resolving a temporary issue. To manage this, create exceptions for known IT personnel or specific administrative actions that are part of regular account maintenance.
* Automated processes or scripts that unsuspend accounts as part of a workflow can also lead to false positives. Identify and document these processes, then exclude them from triggering alerts by using specific identifiers or tags associated with the automation.
* User accounts that are temporarily suspended due to policy violations or inactivity and later reinstated can cause false positives. Implement a review process to verify the legitimacy of these reinstatements and adjust the rule to exclude such cases when they are part of a documented policy.

**Response and remediation**

* Immediately review the user account activity logs to determine if any unauthorized actions were taken after the account was unsuspended. Focus on sensitive data access and changes to security settings.
* Temporarily suspend the user account again to prevent further unauthorized access while the investigation is ongoing.
* Notify the security team and relevant stakeholders about the potential security incident to ensure coordinated response efforts.
* Conduct a thorough review of the account’s permissions and access levels to ensure they align with the user’s current role and responsibilities. Adjust as necessary to follow the principle of least privilege.
* If malicious activity is confirmed, initiate a password reset for the affected account and any other accounts that may have been compromised.
* Implement additional monitoring on the affected account and similar accounts to detect any further suspicious activity.
* Review and update security policies and procedures related to account suspension and reactivation to prevent similar incidents in the future.

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://docs/reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_1054]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5201]

```js
event.dataset:google_workspace.admin and event.category:iam and event.action:UNSUSPEND_USER
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



