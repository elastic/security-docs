---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unauthorized-access-to-an-okta-application.html
---

# Unauthorized Access to an Okta Application [unauthorized-access-to-an-okta-application]

Identifies unauthorized access attempts to Okta applications.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Initial Access
* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 411

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1089]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unauthorized Access to an Okta Application**

Okta is a widely used identity management service that facilitates secure user authentication and access to applications. Adversaries may exploit valid credentials to gain unauthorized access, bypassing security controls. The detection rule monitors specific Okta system events for unauthorized access attempts, leveraging event datasets and actions to identify potential breaches, thus aiding in early threat detection and response.

**Possible investigation steps**

* Review the event logs for entries with event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt to identify the specific unauthorized access attempts.
* Identify the user accounts involved in the unauthorized access attempts and check for any unusual activity or patterns associated with these accounts.
* Investigate the source IP addresses associated with the unauthorized access attempts to determine if they are known or suspicious, and check for any geolocation anomalies.
* Examine the timestamps of the unauthorized access attempts to see if they coincide with any other suspicious activities or known incidents.
* Check for any recent changes in user permissions or configurations in the Okta system that might have facilitated the unauthorized access attempts.
* Contact the affected users to verify if they were aware of the access attempts and to ensure their credentials have not been compromised.

**False positive analysis**

* Employees accessing applications from new devices or locations may trigger alerts. Regularly update the list of known devices and locations to minimize these false positives.
* Automated scripts or tools used for application testing might mimic unauthorized access attempts. Identify and whitelist these scripts to prevent unnecessary alerts.
* Users with multiple accounts accessing the same application can be mistaken for unauthorized access. Maintain an updated list of legitimate multi-account users to reduce false positives.
* Changes in user roles or permissions might lead to temporary access issues. Coordinate with HR or IT departments to ensure role changes are reflected promptly in the system.
* Scheduled maintenance or updates to applications can generate access attempts that appear unauthorized. Exclude these events by aligning detection rules with maintenance schedules.

**Response and remediation**

* Immediately isolate the affected user account by disabling it to prevent further unauthorized access.
* Review and reset the credentials for the compromised account, ensuring the new password adheres to strong security policies.
* Conduct a thorough audit of recent activities associated with the compromised account to identify any unauthorized changes or data access.
* Notify the affected user and relevant stakeholders about the incident, providing guidance on recognizing phishing attempts and securing their accounts.
* Escalate the incident to the security operations team for further investigation and to determine if additional accounts or systems have been compromised.
* Implement multi-factor authentication (MFA) for the affected account and any other accounts that do not currently have it enabled to enhance security.
* Update and refine monitoring rules to detect similar unauthorized access attempts in the future, ensuring quick identification and response.


## Setup [_setup_687]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_1145]

```js
event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



