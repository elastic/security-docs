---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-attempted-bypass-of-okta-mfa.html
---

# Attempted Bypass of Okta MFA [prebuilt-rule-8-4-1-attempted-bypass-of-okta-mfa]

Detects attempts to bypass Okta multi-factor authentication (MFA). An adversary may attempt to bypass the Okta MFA policies configured for an organization in order to obtain unauthorized access to an application.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2625]



## Rule query [_rule_query_3011]

```js
event.dataset:okta.system and event.action:user.mfa.attempt_bypass
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Multi-Factor Authentication Interception
    * ID: T1111
    * Reference URL: [https://attack.mitre.org/techniques/T1111/](https://attack.mitre.org/techniques/T1111/)



