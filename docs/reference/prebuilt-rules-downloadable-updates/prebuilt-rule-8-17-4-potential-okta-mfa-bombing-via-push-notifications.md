---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-okta-mfa-bombing-via-push-notifications.html
---

# Potential Okta MFA Bombing via Push Notifications [prebuilt-rule-8-17-4-potential-okta-mfa-bombing-via-push-notifications]

Detects when an attacker abuses the Multi-Factor authentication mechanism by repeatedly issuing login requests until the user eventually accepts the Okta push notification. An adversary may attempt to bypass the Okta MFA policies configured for an organization to obtain unauthorized access.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.mandiant.com/resources/russian-targeting-gov-business](https://www.mandiant.com/resources/russian-targeting-gov-business)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.rezonate.io/blog/okta-logs-decoded-unveiling-identity-threats-through-threat-hunting/](https://www.rezonate.io/blog/okta-logs-decoded-unveiling-identity-threats-through-threat-hunting/)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4253]

**Triage and analysis**

**Investigating Potential Okta MFA Bombing via Push Notifications**

Multi-Factor Authentication (MFA) is an effective method to prevent unauthorized access. However, some adversaries may abuse the system by repeatedly sending MFA push notifications until the user unwittingly approves the access.

This rule detects when a user denies MFA Okta Verify push notifications twice, followed by a successful authentication event within a 10-minute window. This sequence could indicate an adversary’s attempt to bypass the Okta MFA policy.

**Possible investigation steps:**

* Identify the user who received the MFA notifications by reviewing the `user.email` field.
* Identify the time, source IP, and geographical location of the MFA requests and the subsequent successful login.
* Review the `event.action` field to understand the nature of the events. It should include two `user.mfa.okta_verify.deny_push` actions and one `user.authentication.sso` action.
* Ask the user if they remember receiving the MFA notifications and subsequently logging into their account.
* Check if the MFA requests and the successful login occurred during the user’s regular activity hours.
* Look for any other suspicious activity on the account around the same time.
* Identify whether the same pattern is repeated for other users in your organization. Multiple users receiving push notifications simultaneously might indicate a larger attack.

**False positive analysis:**

* Determine if the MFA push notifications were legitimate. Sometimes, users accidentally trigger MFA requests or deny them unintentionally and later approve them.
* Check if there are known issues with the MFA system causing false denials.

**Response and remediation:**

* If unauthorized access is confirmed, initiate your incident response process.
* Alert the user and your IT department immediately.
* If possible, isolate the user’s account until the issue is resolved.
* Investigate the source of the unauthorized access.
* If the account was accessed by an unauthorized party, determine the actions they took after logging in.
* Consider enhancing your MFA policy to prevent such incidents in the future.
* Encourage users to report any unexpected MFA notifications immediately.
* Review and update your incident response plans and security policies based on the findings from the incident.


## Setup [_setup_1112]

**Setup**

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5251]

```js
sequence by okta.actor.id with maxspan=10m
  [authentication where event.dataset == "okta.system"
    and okta.event_type == "user.mfa.okta_verify.deny_push"] with runs=5
  until [authentication where event.dataset == "okta.system"
    and (okta.event_type: (
      "user.authentication.sso",
      "user.authentication.auth_via_mfa",
      "user.authentication.verify",
      "user.session.start") and okta.outcome.result == "SUCCESS")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Multi-Factor Authentication Request Generation
    * ID: T1621
    * Reference URL: [https://attack.mitre.org/techniques/T1621/](https://attack.mitre.org/techniques/T1621/)



