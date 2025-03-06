---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-iam-group-creation.html
---

# AWS IAM Group Creation [prebuilt-rule-8-2-1-aws-iam-group-creation]

Identifies the creation of a group in AWS Identity and Access Management (IAM). Groups specify permissions for multiple users. Any user in a group automatically has the permissions that are assigned to the group.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-group.html)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1873]



## Rule query [_rule_query_2158]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:CreateGroup and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Cloud Account
    * ID: T1136.003
    * Reference URL: [https://attack.mitre.org/techniques/T1136/003/](https://attack.mitre.org/techniques/T1136/003/)



