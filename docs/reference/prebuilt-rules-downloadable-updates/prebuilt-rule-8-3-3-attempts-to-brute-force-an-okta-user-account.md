---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-attempts-to-brute-force-an-okta-user-account.html
---

# Attempts to Brute Force an Okta User Account [prebuilt-rule-8-3-3-attempts-to-brute-force-an-okta-user-account]

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
* @BenB196
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2915]



## Rule query [_rule_query_3336]

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



