---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-kms-customer-managed-key-disabled-or-scheduled-for-deletion.html
---

# AWS KMS Customer Managed Key Disabled or Scheduled for Deletion [prebuilt-rule-8-4-1-aws-kms-customer-managed-key-disabled-or-scheduled-for-deletion]

Identifies attempts to disable or schedule the deletion of an AWS KMS Customer Managed Key (CMK). Deleting an AWS KMS key is destructive and potentially dangerous. It deletes the key material and all metadata associated with the KMS key and is irreversible. After a KMS key is deleted, the data that was encrypted under that KMS key can no longer be decrypted, which means that data becomes unrecoverable.

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

* [https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html](https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html)
* [https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing
* Impact

**Version**: 1

**Rule authors**:

* Xavier Pich

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2569]



## Rule query [_rule_query_2953]

```js
event.dataset:aws.cloudtrail and event.provider:kms.amazonaws.com and event.action:("DisableKey" or "ScheduleKeyDeletion") and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



