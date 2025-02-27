---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-o365-excessive-single-sign-on-logon-errors.html
---

# O365 Excessive Single Sign-On Logon Errors [prebuilt-rule-1-0-2-o365-excessive-single-sign-on-logon-errors]

Identifies accounts with a high number of single sign-on (SSO) logon errors. Excessive logon errors may indicate an attempt to brute force a password or SSO token.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1443]

## Config

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1674]

```js
event.dataset:o365.audit and event.provider:AzureActiveDirectory and event.category:authentication and o365.audit.LogonError:"SsoArtifactInvalidOrExpired"
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



