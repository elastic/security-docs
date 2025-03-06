---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-aws-ec2-network-access-control-list-creation.html
---

# AWS EC2 Network Access Control List Creation [prebuilt-rule-1-0-2-aws-ec2-network-access-control-list-creation]

Identifies the creation of an AWS Elastic Compute Cloud (EC2) network access control list (ACL) or an entry in a network ACL with a specified rule number.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.html)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.html)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html)

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

## Investigation guide [_investigation_guide_1408]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1639]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
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



