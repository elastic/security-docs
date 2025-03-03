---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-rds-cluster-creation.html
---

# AWS RDS Cluster Creation [prebuilt-rule-8-2-1-aws-rds-cluster-creation]

Identifies the creation of a new Amazon Relational Database Service (RDS) Aurora DB cluster or global database spread across multiple regions.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-db-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-global-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-global-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateGlobalCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateGlobalCluster.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1874]



## Rule query [_rule_query_2159]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(CreateDBCluster or CreateGlobalCluster) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



