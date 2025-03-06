---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-route53-private-hosted-zone-associated-with-a-vpc.html
---

# AWS Route53 private hosted zone associated with a VPC [prebuilt-rule-8-2-1-aws-route53-private-hosted-zone-associated-with-a-vpc]

Identifies when a Route53 private hosted zone has been associated with VPC.

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

* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_AssociateVPCWithHostedZone.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_AssociateVPCWithHostedZone.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 3

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1880]



## Rule query [_rule_query_2165]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:AssociateVPCWithHostedZone and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



