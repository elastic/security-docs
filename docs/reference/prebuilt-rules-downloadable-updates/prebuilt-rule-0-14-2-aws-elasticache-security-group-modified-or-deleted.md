---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-aws-elasticache-security-group-modified-or-deleted.html
---

# AWS ElastiCache Security Group Modified or Deleted [prebuilt-rule-0-14-2-aws-elasticache-security-group-modified-or-deleted]

Identifies when an ElastiCache security group has been modified or deleted.

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

* [https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/Welcome.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/Welcome.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 1

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1290]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1388]

```js
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:("Delete Cache Security Group" or
"Authorize Cache Security Group Ingress" or  "Revoke Cache Security Group Ingress" or "AuthorizeCacheSecurityGroupEgress" or
"RevokeCacheSecurityGroupEgress") and event.outcome:success
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

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



