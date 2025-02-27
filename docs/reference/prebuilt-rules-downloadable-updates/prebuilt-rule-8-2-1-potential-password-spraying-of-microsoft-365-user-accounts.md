---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-potential-password-spraying-of-microsoft-365-user-accounts.html
---

# Potential Password Spraying of Microsoft 365 User Accounts [prebuilt-rule-8-2-1-potential-password-spraying-of-microsoft-365-user-accounts]

Identifies a high number (25) of failed Microsoft 365 user authentication attempts from a single IP address within 30 minutes, which could be indicative of a password spraying attack. An adversary may attempt a password spraying attack to obtain unauthorized access to user accounts.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1971]



## Rule query [_rule_query_2256]

```js
event.dataset:o365.audit and event.provider:(Exchange or AzureActiveDirectory) and event.category:authentication and
event.action:("UserLoginFailed" or "PasswordLogonInitialAuthUsingPassword")
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



