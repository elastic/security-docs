---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-1-attempts-to-brute-force-a-microsoft-365-user-account.html
---

# Attempts to Brute Force a Microsoft 365 User Account [prebuilt-rule-0-13-1-attempts-to-brute-force-a-microsoft-365-user-account]

Identifies attempts to brute force a Microsoft 365 user account. An adversary may attempt a brute force attack to obtain unauthorized access to user accounts.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: high

**Risk score**: 73

**Runs every**: None

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1218]

## Config

The Microsoft 365 Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1250]

```js
event.dataset:o365.audit and event.provider:(Exchange or AzureActiveDirectory) and event.category:authentication and
event.action:("UserLoginFailed" or "PasswordLogonInitialAuthUsingPassword") and event.outcome:failure
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



