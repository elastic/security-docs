---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/okta-brute-force-or-password-spraying-attack.html
---

# Okta Brute Force or Password Spraying Attack [okta-brute-force-or-password-spraying-attack]

Identifies a high number of failed Okta user authentication attempts from a single IP address, which could be indicative of a brute force or password spraying attack. An adversary may attempt a brute force or password spraying attack to obtain unauthorized access to user accounts.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

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

* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 413

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_602]

**Triage and analysis**

**Investigating Okta Brute Force or Password Spraying Attack**

This rule alerts when a high number of failed Okta user authentication attempts occur from a single IP address. This could be indicative of a brute force or password spraying attack, where an adversary may attempt to gain unauthorized access to user accounts by guessing the passwords.

**Possible investigation steps:**

* Review the `source.ip` field to identify the IP address from which the high volume of failed login attempts originated.
* Look into the `event.outcome` field to verify that these are indeed failed authentication attempts.
* Determine the `user.name` or `user.email` related to these failed login attempts. If the attempts are spread across multiple accounts, it might indicate a password spraying attack.
* Check the timeline of the events. Are the failed attempts spread out evenly, or are there burst periods, which might indicate an automated tool?
* Determine the geographical location of the source IP. Is this location consistent with the user’s typical login location?
* Analyze any previous successful logins from this IP. Was this IP previously associated with successful logins?

**False positive analysis:**

* A single user or automated process that attempts to authenticate using expired or wrong credentials multiple times may trigger a false positive.
* Analyze the behavior of the source IP. If the IP is associated with legitimate users or services, it may be a false positive.

**Response and remediation:**

* If you identify unauthorized access attempts, consider blocking the source IP at the firewall level.
* Notify the users who are targeted by the attack. Ask them to change their passwords and ensure they use unique, complex passwords.
* Enhance monitoring on the affected user accounts for any suspicious activity.
* If the attack is persistent, consider implementing CAPTCHA or account lockouts after a certain number of failed login attempts.
* If the attack is persistent, consider implementing multi-factor authentication (MFA) for the affected user accounts.
* Review and update your security policies based on the findings from the incident.


## Setup [_setup_388]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_644]

```js
event.dataset:okta.system and event.category:authentication and event.outcome:failure
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



