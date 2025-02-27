---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-efs-file-system-or-mount-deleted.html
---

# AWS EFS File System or Mount Deleted [prebuilt-rule-8-2-1-aws-efs-file-system-or-mount-deleted]

Detects when an EFS File System or Mount is deleted. An adversary could break any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts. The mount must be deleted prior to deleting the File System, or the adversary will be unable to delete the File System.

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

* [https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html](https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.md)
* [https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html](https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Data Protection

**Version**: 5

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1857]



## Rule query [_rule_query_2147]

```js
event.dataset:aws.cloudtrail and event.provider:elasticfilesystem.amazonaws.com and
event.action:(DeleteMountTarget or DeleteFileSystem) and event.outcome:success
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



