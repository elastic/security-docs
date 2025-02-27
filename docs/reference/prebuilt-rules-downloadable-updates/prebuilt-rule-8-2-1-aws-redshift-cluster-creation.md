---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-redshift-cluster-creation.html
---

# AWS Redshift Cluster Creation [prebuilt-rule-8-2-1-aws-redshift-cluster-creation]

Identifies the creation of an Amazon Redshift cluster. Unexpected creation of this cluster by a non-administrative user may indicate a permission or role issue with current users. If unexpected, the resource may not properly be configured and could introduce security vulnerabilities.

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

* [https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html](https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility
* Persistence

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1877]



## Rule query [_rule_query_2162]

```js
event.dataset:aws.cloudtrail and event.provider:redshift.amazonaws.com and event.action:CreateCluster and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



