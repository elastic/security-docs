---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/cyberark-privileged-access-security-error.html
---

# CyberArk Privileged Access Security Error [cyberark-privileged-access-security-error]

Identifies the occurrence of a CyberArk Privileged Access Security (PAS) error level audit event. The event.code correlates to the CyberArk Vault Audit Action Code.

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

* [https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASREF/Vault%20Audit%20Action%20Codes.htm?tocpath=Administration%7CReferences%7C*_*3](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASREF/Vault%20Audit%20Action%20Codes.htm?tocpath=Administration%7CReferences%7C*_*3)

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

## Investigation guide [_investigation_guide_255]

**Triage and analysis**

This is a promotion rule for CyberArk error events, which are alertable events per the vendor. Consult vendor documentation on interpreting specific events.


## Setup [_setup_168]

The CyberArk Privileged Access Security (PAS) Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_266]

```js
event.dataset:cyberarkpas.audit and event.type:error
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



