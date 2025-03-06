---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-iam-group-deletion.html
---

# AWS IAM Group Deletion [prebuilt-rule-8-2-1-aws-iam-group-deletion]

Identifies the deletion of a specified AWS Identity and Access Management (IAM) resource group. Deleting a resource group does not delete resources that are members of the group; it only deletes the group structure.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1859]



## Rule query [_rule_query_2149]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:DeleteGroup and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



