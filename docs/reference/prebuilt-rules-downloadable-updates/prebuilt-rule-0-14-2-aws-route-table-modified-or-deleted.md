---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-aws-route-table-modified-or-deleted.html
---

# AWS Route Table Modified or Deleted [prebuilt-rule-0-14-2-aws-route-table-modified-or-deleted]

Identifies when an AWS Route Table has been modified or deleted.

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

* [https://github.com/easttimor/aws-incident-response#network-routing](https://github.com/easttimor/aws-incident-response#network-routing)
* [https://docs.datadoghq.com/security_platform/default_rules/cloudtrail-aws-route-table-modified](https://docs.datadoghq.com/security_platform/default_rules/cloudtrail-aws-route-table-modified)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRoute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRoute.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRouteTableAssociation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRouteTableAssociation)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRouteTable.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRouteTable.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRoute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRoute.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisassociateRouteTable.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisassociateRouteTable.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 1

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1291]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1389]

```js
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(ReplaceRoute or ReplaceRouteTableAssociation or
DeleteRouteTable or DeleteRoute or DisassociateRouteTable) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



