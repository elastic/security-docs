---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-o365-excessive-single-sign-on-logon-errors.html
---

# O365 Excessive Single Sign-On Logon Errors [prebuilt-rule-8-17-4-o365-excessive-single-sign-on-logon-errors]

Identifies accounts with a high number of single sign-on (SSO) logon errors. Excessive logon errors may indicate an attempt to brute force a password or SSO token.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4218]

**Triage and analysis**

[TBC: QUOTE]
**Investigating O365 Excessive Single Sign-On Logon Errors**

Single Sign-On (SSO) in O365 streamlines user access by allowing one set of credentials for multiple applications. However, adversaries may exploit this by attempting brute force attacks to gain unauthorized access. The detection rule monitors for frequent SSO logon errors, signaling potential abuse, and helps identify compromised accounts by flagging unusual authentication patterns.

**Possible investigation steps**

* Review the specific account(s) associated with the excessive SSO logon errors by examining the event logs filtered by the query fields, particularly focusing on the o365.audit.LogonError field with the value "SsoArtifactInvalidOrExpired".
* Analyze the timestamps of the logon errors to determine if there is a pattern or specific time frame when the errors are occurring, which might indicate a targeted attack.
* Check for any recent changes or unusual activities in the affected account(s), such as password changes, unusual login locations, or device changes, to assess if the account might be compromised.
* Investigate the source IP addresses associated with the logon errors to identify if they are from known malicious sources or unusual locations for the user.
* Correlate the logon error events with other security alerts or logs from the same time period to identify any related suspicious activities or potential indicators of compromise.
* Contact the user(s) of the affected account(s) to verify if they experienced any issues with their account access or if they recognize the logon attempts, which can help determine if the activity is legitimate or malicious.

**False positive analysis**

* High volume of legitimate user logins: Users who frequently log in and out of multiple O365 applications may trigger excessive logon errors. To manage this, create exceptions for known high-activity accounts.
* Automated scripts or applications: Some automated processes may use outdated or incorrect credentials, leading to repeated logon errors. Identify and update these scripts to prevent false positives.
* Password changes: Users who recently changed their passwords might experience logon errors if they have not updated their credentials across all devices and applications. Encourage users to update their credentials promptly.
* Network issues: Temporary network disruptions can cause authentication errors. Monitor network stability and consider excluding errors during known network maintenance periods.
* Multi-factor authentication (MFA) misconfigurations: Incorrect MFA settings can lead to logon errors. Verify and correct MFA configurations for affected users to reduce false positives.

**Response and remediation**

* Immediately isolate the affected account by disabling it to prevent further unauthorized access attempts.
* Conduct a password reset for the compromised account and enforce a strong password policy to mitigate the risk of future brute force attacks.
* Review and analyze the account’s recent activity logs to identify any unauthorized access or data exfiltration attempts.
* Implement multi-factor authentication (MFA) for the affected account and other high-risk accounts to add an additional layer of security.
* Notify the user of the affected account about the incident and provide guidance on recognizing phishing attempts and securing their credentials.
* Escalate the incident to the security operations team for further investigation and to determine if additional accounts or systems have been compromised.
* Update and enhance monitoring rules to detect similar patterns of excessive SSO logon errors, ensuring early detection of potential brute force attempts.


## Setup [_setup_1079]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5216]

```js
event.dataset:o365.audit and event.provider:AzureActiveDirectory and event.category:authentication and o365.audit.LogonError:"SsoArtifactInvalidOrExpired"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)



