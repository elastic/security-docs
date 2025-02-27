---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-microsoft-365-user-restricted-from-sending-email.html
---

# Microsoft 365 User Restricted from Sending Email [prebuilt-rule-1-0-2-microsoft-365-user-restricted-from-sending-email]

Identifies when a user has been restricted from sending email due to exceeding sending limits of the service policies per the Security Compliance Center.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy](https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy)
* [https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference](https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference)

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 2

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1456]

## Config

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1687]

```js
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
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



