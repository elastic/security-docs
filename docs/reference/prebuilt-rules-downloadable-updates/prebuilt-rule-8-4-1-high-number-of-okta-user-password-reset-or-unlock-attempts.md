---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-high-number-of-okta-user-password-reset-or-unlock-attempts.html
---

# High Number of Okta User Password Reset or Unlock Attempts [prebuilt-rule-8-4-1-high-number-of-okta-user-password-reset-or-unlock-attempts]

Identifies a high number of Okta user password reset or account unlock attempts. An adversary may attempt to obtain unauthorized access to Okta user accounts using these methods and attempt to blend in with normal activity in their target’s environment and evade detection.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_2639]



## Rule query [_rule_query_3025]

```js
event.dataset:okta.system and
  event.action:(system.email.account_unlock.sent_message or system.email.password_reset.sent_message or
                system.sms.send_account_unlock_message or system.sms.send_password_reset_message or
                system.voice.send_account_unlock_call or system.voice.send_password_reset_call or
                user.account.unlock_token)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



