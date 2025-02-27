---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-password-spraying-of-microsoft-365-user-accounts.html
---

# Potential Password Spraying of Microsoft 365 User Accounts [prebuilt-rule-1-0-2-potential-password-spraying-of-microsoft-365-user-accounts]

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1442]

## Config

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1673]

```js
event.dataset:o365.audit and event.provider:(Exchange or AzureActiveDirectory) and event.category:authentication and
event.action:("UserLoginFailed" or "PasswordLogonInitialAuthUsingPassword") and event.outcome:success
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



