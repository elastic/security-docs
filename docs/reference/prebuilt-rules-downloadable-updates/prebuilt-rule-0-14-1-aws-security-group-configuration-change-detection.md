---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-aws-security-group-configuration-change-detection.html
---

# AWS Security Group Configuration Change Detection [prebuilt-rule-0-14-1-aws-security-group-configuration-change-detection]

Identifies a change to an AWS Security Group Configuration. A security group is like a virtul firewall and modifying configurations may allow unauthorized access. Threat actors may abuse this to establish persistence, exfiltrate data, or pivot in a AWS environment.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html)

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

## Investigation guide [_investigation_guide_1254]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1328]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:(AuthorizeSecurityGroupEgress or
CreateSecurityGroup or ModifyInstanceAttribute or ModifySecurityGroupRules or RevokeSecurityGroupEgress or
RevokeSecurityGroupIngress) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



