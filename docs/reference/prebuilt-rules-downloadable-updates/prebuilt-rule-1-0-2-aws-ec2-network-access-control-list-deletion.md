---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-aws-ec2-network-access-control-list-deletion.html
---

# AWS EC2 Network Access Control List Deletion [prebuilt-rule-1-0-2-aws-ec2-network-access-control-list-deletion]

Identifies the deletion of an Amazon Elastic Compute Cloud (EC2) network access control list (ACL) or one of its ingress/egress entries.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl-entry.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl-entry.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1391]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1624]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
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

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



