---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-time-seen-google-workspace-oauth-login-from-third-party-application.html
---

# First Time Seen Google Workspace OAuth Login from Third-Party Application [first-time-seen-google-workspace-oauth-login-from-third-party-application]

Detects the first time a third-party application logs in and authenticated with OAuth. OAuth is used to grant permissions to specific resources and services in Google Workspace. Compromised credentials or service accounts could allow an adversary to authenticate to Google Workspace as a valid user and inherit their privileges.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)
* [https://developers.google.com/apps-script/guides/bound](https://developers.google.com/apps-script/guides/bound)
* [https://developers.google.com/identity/protocols/oauth2](https://developers.google.com/identity/protocols/oauth2)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Tactic: Defense Evasion
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_347]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Time Seen Google Workspace OAuth Login from Third-Party Application**

OAuth is a protocol that allows third-party applications to access user data without exposing credentials, enhancing security in Google Workspace. However, adversaries can exploit OAuth by using compromised credentials to gain unauthorized access, mimicking legitimate users. The detection rule identifies unusual OAuth logins by monitoring authorization events linked to new third-party applications, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the event details to identify the specific third-party application involved by examining the google_workspace.token.client.id field.
* Check the google_workspace.token.scope.data field to understand the scope of permissions granted to the third-party application and assess if they align with expected usage.
* Investigate the user account associated with the OAuth authorization event to determine if there are any signs of compromise or unusual activity.
* Correlate the timestamp of the OAuth login event with other security logs to identify any concurrent suspicious activities or anomalies.
* Verify if the third-party application is known and authorized within the organization by consulting with relevant stakeholders or reviewing application whitelists.
* Assess the risk and impact of the OAuth login by considering the privileges of the user account and the sensitivity of the accessed resources.

**False positive analysis**

* New legitimate third-party applications: Users may frequently integrate new third-party applications for productivity or collaboration. To manage this, maintain a whitelist of known and trusted applications and exclude them from triggering alerts.
* Regular updates to existing applications: Some applications may update their OAuth client IDs during version upgrades. Monitor application update logs and adjust the detection rule to exclude these known updates.
* Internal development and testing: Organizations developing their own applications may trigger this rule during testing phases. Coordinate with development teams to identify and exclude these internal applications from alerts.
* Frequent use of service accounts: Service accounts used for automation or integration purposes might appear as new logins. Document and exclude these service accounts from the detection rule to prevent false positives.

**Response and remediation**

* Immediately revoke the OAuth token associated with the suspicious third-party application to prevent further unauthorized access.
* Conduct a thorough review of the affected user’s account activity to identify any unauthorized actions or data access that may have occurred.
* Reset the credentials of the affected user and any other users who may have been compromised, ensuring that strong, unique passwords are used.
* Notify the affected user and relevant stakeholders about the incident, providing guidance on recognizing phishing attempts and securing their accounts.
* Implement additional monitoring for the affected user and similar OAuth authorization events to detect any further suspicious activity.
* Escalate the incident to the security operations team for a deeper investigation into potential lateral movement or data exfiltration.
* Review and update OAuth application permissions and policies to ensure that only trusted applications have access to sensitive data and services.

**Setup**

**Important Information Regarding Google Workspace Event Lag Times**

* As per Google’s documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event’s occurrence and the event being visible in the Google Workspace admin/audit logs.
* This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
* To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google’s reporting API for new events.
* By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
* See the following references for further information:
* [https://support.google.com/a/answer/7061566](https://support.google.com/a/answer/7061566)
* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md](beats://reference/filebeat/filebeat-module-google_workspace.md)


## Setup [_setup_214]

The Google Workspace Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_379]

```js
event.dataset: "google_workspace.token" and event.action: "authorize" and
google_workspace.token.scope.data: *Login and google_workspace.token.client.id: *apps.googleusercontent.com
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)

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



