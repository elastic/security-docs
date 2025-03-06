---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-guardduty-detector-deletion.html
---

# AWS GuardDuty Detector Deletion [prebuilt-rule-8-2-1-aws-guardduty-detector-deletion]

Identifies the deletion of an Amazon GuardDuty detector. Upon deletion, GuardDuty stops monitoring the environment and all existing findings are lost.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/guardduty/delete-detector.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/guardduty/delete-detector.html)
* [https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1843]



## Rule query [_rule_query_2133]

```js
event.dataset:aws.cloudtrail and event.provider:guardduty.amazonaws.com and event.action:DeleteDetector and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



