---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-abuse-of-repeated-mfa-push-notifications.html
---

# Potential Abuse of Repeated MFA Push Notifications [prebuilt-rule-8-4-1-potential-abuse-of-repeated-mfa-push-notifications]

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

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2627]



## Rule query [_rule_query_3013]

```js
sequence by user.email with maxspan=10m
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.authentication.sso"]
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



