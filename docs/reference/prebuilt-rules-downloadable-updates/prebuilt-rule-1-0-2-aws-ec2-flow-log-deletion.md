---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-aws-ec2-flow-log-deletion.html
---

# AWS EC2 Flow Log Deletion [prebuilt-rule-1-0-2-aws-ec2-flow-log-deletion]

Identifies the deletion of one or more flow logs in AWS Elastic Compute Cloud (EC2). An adversary may delete flow logs in an attempt to evade defenses.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1390]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1623]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
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



