---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/cyberark-privileged-access-security-recommended-monitor.html
---

# CyberArk Privileged Access Security Recommended Monitor [cyberark-privileged-access-security-recommended-monitor]

Identifies the occurrence of a CyberArk Privileged Access Security (PAS) non-error level audit event which is recommended for monitoring by the vendor. The event.code correlates to the CyberArk Vault Audit Action Code.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-cyberarkpas.audit*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASREF/Vault%20Audit%20Action%20Codes.htm?tocpath=Administration%7CReferences%7C*_*3#RecommendedActionCodesforMonitoring](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASREF/Vault%20Audit%20Action%20Codes.htm?tocpath=Administration%7CReferences%7C*_*3#RecommendedActionCodesforMonitoring)

**Tags**:

* Data Source: CyberArk PAS
* Use Case: Log Auditing
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_256]

**Triage and analysis**

This is a promotion rule for CyberArk events, which the vendor recommends should be monitored. Consult vendor documentation on interpreting specific events.


## Setup [_setup_169]

The CyberArk Privileged Access Security (PAS) Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_267]

```js
event.dataset:cyberarkpas.audit and
  event.code:(4 or 22 or 24 or 31 or 38 or 57 or 60 or 130 or 295 or 300 or 302 or
              308 or 319 or 344 or 346 or 359 or 361 or 378 or 380 or 411) and
  not event.type:error
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)



