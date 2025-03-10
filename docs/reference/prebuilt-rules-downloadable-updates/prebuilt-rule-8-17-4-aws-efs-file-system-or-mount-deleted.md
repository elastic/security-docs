---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-efs-file-system-or-mount-deleted.html
---

# AWS EFS File System or Mount Deleted [prebuilt-rule-8-17-4-aws-efs-file-system-or-mount-deleted]

Detects when an EFS File System or Mount is deleted. An adversary could break any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts. The mount must be deleted prior to deleting the File System, or the adversary will be unable to delete the File System.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html](https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.md)
* [https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html](https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4022]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EFS File System or Mount Deleted**

Amazon Elastic File System (EFS) provides scalable file storage for use with AWS cloud services and on-premises resources. Adversaries may target EFS by deleting file systems or mount targets, disrupting applications reliant on these resources. The detection rule monitors AWS CloudTrail logs for successful deletion events, signaling potential malicious activity aimed at data destruction or service disruption.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the deletion event by examining the user identity information in the logs.
* Check the event time and correlate it with other activities in the AWS environment to determine if there are any related suspicious actions or patterns.
* Investigate the source IP address and location from which the deletion request was made to assess if it aligns with expected access patterns or if it appears anomalous.
* Verify if there were any recent changes to IAM policies or roles that might have inadvertently granted permissions to delete EFS resources.
* Assess the impact of the deletion by identifying which applications or services were using the deleted EFS file system or mount target and determine if there are any disruptions.
* Contact the user or team responsible for the AWS account to confirm if the deletion was intentional and authorized, or if it was potentially malicious.

**False positive analysis**

* Routine maintenance activities by system administrators may trigger deletion events. To manage this, create exceptions for known maintenance windows or specific administrator accounts.
* Automated scripts or cloud management tools that manage EFS resources might delete mounts or file systems as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts.
* Development or testing environments often involve frequent creation and deletion of resources. Exclude these environments from the rule to prevent unnecessary alerts.
* Scheduled cleanup jobs that remove unused or temporary file systems can cause false positives. Document these jobs and configure exceptions based on their execution schedule.
* Ensure that any third-party services or integrations with AWS that manage EFS resources are accounted for, and their actions are excluded if they are part of expected behavior.

**Response and remediation**

* Immediately isolate the affected EFS file system to prevent further unauthorized deletions or access. This can be done by modifying the security group rules to deny all traffic temporarily.
* Review AWS CloudTrail logs to identify the source of the deletion request, including the IAM user or role involved, and assess whether the action was authorized.
* Revoke or adjust permissions for the identified IAM user or role to prevent further unauthorized actions. Ensure that least privilege principles are applied.
* Restore the deleted EFS file system or mount from the most recent backup, if available, to minimize data loss and service disruption.
* Notify the incident response team and relevant stakeholders about the incident for further investigation and to ensure awareness across the organization.
* Conduct a post-incident review to identify any gaps in security controls or processes that allowed the unauthorized deletion, and implement necessary improvements.
* Enhance monitoring and alerting for similar events by ensuring that all critical AWS resources have appropriate logging and alerting configured, focusing on deletion and modification actions.


## Setup [_setup_936]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5039]

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



