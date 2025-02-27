---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-rds-snapshot-export.html
---

# AWS RDS Snapshot Export [prebuilt-rule-8-2-1-aws-rds-snapshot-export]

Identifies the export of an Amazon Relational Database Service (RDS) Aurora database snapshot.

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

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility
* Exfiltration

**Version**: 3

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1850]



## Rule query [_rule_query_2140]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



