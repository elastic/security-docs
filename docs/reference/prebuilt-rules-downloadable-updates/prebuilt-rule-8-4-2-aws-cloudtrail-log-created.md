---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-aws-cloudtrail-log-created.html
---

# AWS CloudTrail Log Created [prebuilt-rule-8-4-2-aws-cloudtrail-log-created]

Identifies the creation of an AWS log trail that specifies the settings for delivery of log data.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3242]



## Rule query [_rule_query_3810]

```js
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)



