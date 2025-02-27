---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-microsoft-365-potential-ransomware-activity.html
---

# Microsoft 365 Potential ransomware activity [prebuilt-rule-0-14-2-microsoft-365-potential-ransomware-activity]

Identifies when Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.

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

**Version**: 1

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1294]

## Config

The Microsoft 365 Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1392]

```js
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Potential ransomware activity" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



