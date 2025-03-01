---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-route-table-created.html
---

# AWS Route Table Created [prebuilt-rule-8-2-1-aws-route-table-created]

Identifies when an AWS Route Table has been created.

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

* [https://docs.datadoghq.com/security_platform/default_rules/aws-ec2-route-table-modified/](https://docs.datadoghq.com/security_platform/default_rules/aws-ec2-route-table-modified/)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security
* Persistence

**Version**: 5

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1881]



## Rule query [_rule_query_2166]

```js
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(CreateRoute or CreateRouteTable) and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



