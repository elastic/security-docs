---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempts-to-brute-force-an-okta-user-account.html
---

# Attempts to Brute Force an Okta User Account [attempts-to-brute-force-an-okta-user-account]

Identifies when an Okta user account is locked out 3 times within a 3 hour window. An adversary may attempt a brute force or password spraying attack to obtain unauthorized access to user accounts. The default Okta authentication policy ensures that a user account is locked out after 10 failed authentication attempts.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-180m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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
* @BenB196
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_169]

**Triage and analysis**

**Investigating Attempts to Brute Force an Okta User Account**

Brute force attacks aim to guess user credentials through exhaustive trial-and-error attempts. In this context, Okta accounts are targeted.

This rule fires when an Okta user account has been locked out 3 times within a 3-hour window. This could indicate an attempted brute force or password spraying attack to gain unauthorized access to the user account. Okta’s default authentication policy locks a user account after 10 failed authentication attempts.

**Possible investigation steps:**

* Identify the actor related to the alert by reviewing `okta.actor.alternate_id` field in the alert. This should give the username of the account being targeted.
* Review the `okta.event_type` field to understand the nature of the events that led to the account lockout.
* Check the `okta.severity` and `okta.display_message` fields for more context around the lockout events.
* Look for correlation of events from the same IP address. Multiple lockouts from the same IP address might indicate a single source for the attack.
* If the IP is not familiar, investigate it. The IP could be a proxy, VPN, Tor node, cloud datacenter, or a legitimate IP turned malicious.
* Determine if the lockout events occurred during the user’s regular activity hours. Unusual timing may indicate malicious activity.
* Examine the authentication methods used during the lockout events by checking the `okta.authentication_context.credential_type` field.

**False positive analysis:**

* Determine whether the account owner or an internal user made repeated mistakes in entering their credentials, leading to the account lockout.
* Ensure there are no known network or application issues that might cause these events.

**Response and remediation:**

* Alert the user and your IT department immediately.
* If unauthorized access is confirmed, initiate your incident response process.
* Investigate the source of the attack. If a specific machine or network is compromised, additional steps may need to be taken to address the issue.
* Require the affected user to change their password.
* If the attack is ongoing, consider blocking the IP address initiating the brute force attack.
* Implement account lockout policies to limit the impact of brute force attacks.
* Encourage users to use complex, unique passwords and consider implementing multi-factor authentication.
* Check if the compromised account was used to access or alter any sensitive data or systems.


## Setup [_setup_106]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_174]

```js
event.dataset:okta.system and event.action:user.account.lock
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



