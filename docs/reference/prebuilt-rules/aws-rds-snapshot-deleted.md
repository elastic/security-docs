---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-snapshot-deleted.html
---

# AWS RDS Snapshot Deleted [aws-rds-snapshot-deleted]

Identifies the deletion of an AWS RDS DB snapshot. Snapshots contain a full backup of an entire DB instance. Unauthorized deletion of snapshots can make it impossible to recover critical or sensitive data. This rule detects deleted snapshots and instances modified so that backupRetentionPeriod is set to 0 which disables automated backups and is functionally similar to deleting the system snapshot.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteSnapshot.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteSnapshot.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSnapshot.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSnapshot.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Use Case: Asset Visibility
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_75]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Snapshot Deleted**

AWS RDS snapshots are critical for data recovery, capturing full backups of database instances. Adversaries may delete these snapshots to prevent data restoration, effectively causing data loss. The detection rule monitors AWS CloudTrail logs for successful deletion actions or modifications that disable automated backups, signaling potential malicious activity aimed at data destruction.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the event.action values "DeleteDBSnapshot" or "DeleteDBClusterSnapshot" to determine if the action was authorized or expected.
* Check the timestamp of the deletion event to correlate with any known maintenance activities or incidents that might explain the snapshot deletion.
* Investigate the source IP address and location from which the deletion request was made to identify any anomalies or unauthorized access patterns.
* Examine the AWS IAM policies and permissions associated with the user or role to ensure they have the appropriate level of access and to identify any potential over-permissioning.
* Look for any recent changes in the AWS environment, such as modifications to IAM roles or policies, that could have allowed unauthorized snapshot deletions.
* If the event.action is "ModifyDBInstance" with "backupRetentionPeriod=0", verify if there was a legitimate reason for disabling automated backups and assess the impact on data recovery capabilities.

**False positive analysis**

* Routine maintenance activities by database administrators may involve deleting old or unnecessary snapshots. To manage this, create exceptions for specific user accounts or roles known to perform these tasks regularly.
* Automated scripts or tools used for database management might delete snapshots as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by whitelisting their associated IAM roles or user accounts.
* Testing environments often involve frequent creation and deletion of snapshots. Consider excluding specific RDS instances or environments used solely for testing purposes to reduce noise in alerts.
* Scheduled cleanup jobs that remove outdated snapshots to manage storage costs can trigger false positives. Document these jobs and adjust the detection rule to ignore actions performed by these jobs' IAM roles.

**Response and remediation**

* Immediately revoke access to AWS accounts or roles suspected of unauthorized activity to prevent further malicious actions.
* Restore the deleted RDS snapshots from any available backups or replicas to ensure data recovery and continuity.
* Enable and configure automated backups for the affected RDS instances to prevent future data loss, ensuring the backupRetentionPeriod is set to a non-zero value.
* Conduct a thorough review of AWS CloudTrail logs to identify any unauthorized access patterns or anomalies leading up to the snapshot deletion.
* Escalate the incident to the security operations team for further investigation and to determine if additional AWS resources were compromised.
* Implement stricter IAM policies and multi-factor authentication for accessing AWS RDS resources to enhance security and prevent unauthorized deletions.
* Update and test the incident response plan to include specific procedures for handling AWS RDS snapshot deletions, ensuring rapid response in future incidents.


## Rule query [_rule_query_79]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "rds.amazonaws.com"
    and event.outcome == "success"
    and (
        event.action in ("DeleteDBSnapshot", "DeleteDBClusterSnapshot") or
        (event.action == "ModifyDBInstance" and stringContains(aws.cloudtrail.request_parameters, "backupRetentionPeriod=0"))
    )
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



