---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-auditd-max-failed-login-attempts.html
---

# Auditd Max Failed Login Attempts [prebuilt-rule-8-2-1-auditd-max-failed-login-attempts]

Identifies that the maximum number of failed login attempts has been reached for a user.

**Rule type**: query

**Rule indices**:

* auditbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/linux-pam/linux-pam/blob/0adbaeb273da1d45213134aa271e95987103281c/modules/pam_faillock/pam_faillock.c#L574](https://github.com/linux-pam/linux-pam/blob/0adbaeb273da1d45213134aa271e95987103281c/modules/pam_faillock/pam_faillock.c#L574)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Initial Access

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2609]

```js
event.module:auditd and event.action:"failed-log-in-too-many-times-to"
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

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



