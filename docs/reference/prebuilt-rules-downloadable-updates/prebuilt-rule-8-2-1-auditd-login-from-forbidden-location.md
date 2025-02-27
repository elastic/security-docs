---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-auditd-login-from-forbidden-location.html
---

# Auditd Login from Forbidden Location [prebuilt-rule-8-2-1-auditd-login-from-forbidden-location]

Identifies that a login attempt has happened from a forbidden location.

**Rule type**: query

**Rule indices**:

* auditbeat-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/linux-pam/linux-pam/blob/aac5a8fdc4aa3f7e56335a6343774cc1b63b408d/modules/pam_access/pam_access.c#L412](https://github.com/linux-pam/linux-pam/blob/aac5a8fdc4aa3f7e56335a6343774cc1b63b408d/modules/pam_access/pam_access.c#L412)

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

## Rule query [_rule_query_2610]

```js
event.module:auditd and event.action:"attempted-log-in-from-unusual-place-to"
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



