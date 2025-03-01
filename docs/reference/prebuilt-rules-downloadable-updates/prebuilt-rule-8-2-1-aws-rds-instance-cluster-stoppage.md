---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-rds-instance-cluster-stoppage.html
---

# AWS RDS Instance/Cluster Stoppage [prebuilt-rule-8-2-1-aws-rds-instance-cluster-stoppage]

Identifies that an Amazon Relational Database Service (RDS) cluster or instance has been stopped.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBCluster.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-instance.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-instance.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBInstance.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1862]



## Rule query [_rule_query_2152]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(StopDBCluster or StopDBInstance) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



