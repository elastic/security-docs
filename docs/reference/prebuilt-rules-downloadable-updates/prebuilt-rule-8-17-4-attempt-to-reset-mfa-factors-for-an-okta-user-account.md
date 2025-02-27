---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-reset-mfa-factors-for-an-okta-user-account.html
---

# Attempt to Reset MFA Factors for an Okta User Account [prebuilt-rule-8-17-4-attempt-to-reset-mfa-factors-for-an-okta-user-account]

Detects attempts to reset an Okta user’s enrolled multi-factor authentication (MFA) factors. An adversary may attempt to reset the MFA factors for an Okta user’s account in order to register new MFA factors and abuse the account to blend in with normal activity in the victim’s environment.

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
* [https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know](https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know)

**Tags**:

* Tactic: Persistence
* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4286]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Reset MFA Factors for an Okta User Account**

Okta is a widely used identity management service that provides multi-factor authentication (MFA) to enhance security. Adversaries may attempt to reset MFA factors to register their own, gaining unauthorized access while appearing legitimate. The detection rule identifies such attempts by monitoring specific Okta system events, helping to flag potential account manipulation activities.

**Possible investigation steps**

* Review the Okta system logs for the specific event.action:user.mfa.factor.reset_all to identify the user account involved in the MFA reset attempt.
* Check the timestamp of the event to determine when the reset attempt occurred and correlate it with any other suspicious activities around the same time.
* Investigate the IP address and location associated with the event to assess if it aligns with the user’s typical access patterns or if it appears unusual.
* Examine the user account’s recent activity history for any anomalies or unauthorized access attempts that might indicate compromise.
* Verify if there have been any recent changes to the user’s account settings or permissions that could suggest account manipulation.
* Contact the affected user to confirm whether they initiated the MFA reset or if it was unauthorized, and advise them on securing their account if necessary.

**False positive analysis**

* Routine administrative actions may trigger the rule if IT staff reset MFA factors for legitimate reasons such as assisting users who have lost access to their MFA devices. To manage this, create exceptions for known IT personnel or specific administrative actions.
* User-initiated resets due to lost or changed devices can also appear as suspicious activity. Implement a process to verify user requests and document these instances to differentiate them from malicious attempts.
* Automated scripts or tools used for account management might reset MFA factors as part of their operations. Identify and whitelist these tools to prevent false positives.
* Scheduled security audits or compliance checks that involve resetting MFA factors should be documented and excluded from triggering alerts by setting up time-based exceptions during these activities.

**Response and remediation**

* Immediately disable the affected Okta user account to prevent further unauthorized access.
* Review recent login activity and MFA changes for the affected account to identify any unauthorized access or suspicious behavior.
* Reset the MFA factors for the affected account and ensure that only the legitimate user can re-enroll their MFA devices.
* Notify the legitimate user of the account compromise and advise them to change their password and review their account activity.
* Conduct a security review of the affected user’s permissions and access to sensitive resources to ensure no unauthorized changes were made.
* Escalate the incident to the security operations team for further investigation and to determine if other accounts may be affected.
* Update security monitoring and alerting to enhance detection of similar MFA reset attempts, leveraging the MITRE ATT&CK framework for guidance on persistence and account manipulation tactics.


## Setup [_setup_1143]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5284]

```js
event.dataset:okta.system and event.action:user.mfa.factor.reset_all
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



