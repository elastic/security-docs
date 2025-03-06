---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-aws-deletion-of-rds-instance-or-cluster.html
---

# AWS Deletion of RDS Instance or Cluster [prebuilt-rule-1-0-2-aws-deletion-of-rds-instance-or-cluster]

Identifies the deletion of an Amazon Relational Database Service (RDS) Aurora database cluster, global database cluster, or database instance.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-cluster.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-global-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-global-cluster.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteGlobalCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteGlobalCluster.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-instance.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-instance.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html)

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

## Investigation guide [_investigation_guide_1405]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1638]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance)
and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



