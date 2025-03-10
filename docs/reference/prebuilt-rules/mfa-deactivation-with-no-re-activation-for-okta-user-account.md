---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/mfa-deactivation-with-no-re-activation-for-okta-user-account.html
---

# MFA Deactivation with no Re-Activation for Okta User Account [mfa-deactivation-with-no-re-activation-for-okta-user-account]

Detects multi-factor authentication (MFA) deactivation with no subsequent re-activation for an Okta user account. An adversary may deactivate MFA for an Okta user account in order to weaken the authentication requirements for the account.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-okta.system*

**Severity**: low

**Risk score**: 21

**Runs every**: 6h

**Searches indices from**: now-12h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Persistence
* Use Case: Identity and Access Audit
* Data Source: Okta
* Domain: Cloud
* Resources: Investigation Guide

**Version**: 413

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_485]

**Triage and analysis**

**Investigating MFA Deactivation with no Re-Activation for Okta User Account**

MFA is used to provide an additional layer of security for user accounts. An adversary may achieve MFA deactivation for an Okta user account to achieve persistence.

This rule fires when an Okta user account has MFA deactivated and no subsequent MFA reactivation is observed within 12 hours.

**Possible investigation steps:**

* Identify the actor related to the alert by reviewing `okta.actor.alternate_id` field in the alert. This should give the username of the account being targeted.
* Review `okta.target` or `user.target.full_name` fields to determine if deactivation was performed by a se parate user.
* Using the `okta.actor.alternate_id` field, search  for MFA re-activation events where `okta.event_type` is `user.mfa.factor.activate`.
* Review events where `okta.event_type` is `user.authenticate*` to determine if the user account had suspicious login activity.
* Geolocation details found in `client.geo*` related fields may be useful in determining if the login activity was suspicious for this user.

**False positive steps:**

* Determine with the target user if MFA deactivation was expected.
* Determine if MFA is required for the target user account.

**Response and remediation:**

* If the MFA deactivation was not expected, consider deactivating the user
* This should be followed by resetting the user’s password and re-enabling MFA.
* If the MFA deactivation was expected, consider adding an exception to this rule to filter false positives.
* Investigate the source of the attack. If a specific machine or network is compromised, additional steps may need to be taken to address the issue.
* Encourage users to use complex, unique passwords and consider implementing multi-factor authentication.
* Check if the compromised account was used to access or alter any sensitive data, applications or systems.
* Review the client user-agent to determine if it’s a known custom application that can be whitelisted.


## Setup [_setup_311]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_522]

```js
sequence by okta.actor.id with maxspan=12h
    [any where event.dataset == "okta.system" and okta.event_type in ("user.mfa.factor.deactivate", "user.mfa.factor.reset_all")
        and okta.outcome.reason != "User reset SECURITY_QUESTION factor" and okta.outcome.result == "SUCCESS"]
    ![any where event.dataset == "okta.system" and okta.event_type == "user.mfa.factor.activate"]
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

* Sub-technique:

    * Name: Multi-Factor Authentication
    * ID: T1556.006
    * Reference URL: [https://attack.mitre.org/techniques/T1556/006/](https://attack.mitre.org/techniques/T1556/006/)



