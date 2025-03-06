---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-deletion-of-rds-instance-or-cluster.html
---

# AWS Deletion of RDS Instance or Cluster [aws-deletion-of-rds-instance-or-cluster]

Identifies the deletion of an Amazon Relational Database Service (RDS) Aurora database cluster, global database cluster, or database instance.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-cluster.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-global-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-global-cluster.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteGlobalCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteGlobalCluster.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-instance.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/delete-db-instance.html)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Use Case: Asset Visibility
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_20]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Deletion of RDS Instance or Cluster**

Amazon RDS simplifies database management by automating tasks like setup and scaling. However, adversaries can exploit this by deleting RDS instances or clusters, causing data loss and service disruption. The detection rule monitors AWS CloudTrail logs for successful deletion actions, alerting security teams to potential malicious activity aimed at data destruction.

**Possible investigation steps**

* Review the AWS CloudTrail logs to confirm the event details, focusing on the event.provider as rds.amazonaws.com and event.action values such as DeleteDBCluster, DeleteGlobalCluster, or DeleteDBInstance.
* Identify the user or role responsible for the deletion by examining the user identity information in the CloudTrail logs, and verify if the action aligns with their typical behavior or responsibilities.
* Check the event time and correlate it with any other suspicious activities or alerts in the AWS environment to determine if the deletion is part of a broader attack pattern.
* Investigate the context of the deletion by reviewing recent changes or activities in the AWS account, such as IAM policy changes or unusual login attempts, to assess if the account may have been compromised.
* Assess the impact of the deletion by identifying the specific RDS instance or cluster affected and determining the potential data loss or service disruption caused by the action.
* Contact the responsible team or individual to verify if the deletion was intentional and authorized, and if not, initiate incident response procedures to mitigate further risk.

**False positive analysis**

* Routine maintenance activities by database administrators can trigger alerts when they intentionally delete RDS instances or clusters. To manage this, create exceptions for known maintenance windows or specific administrator actions.
* Automated scripts or tools used for testing and development purposes might delete RDS resources as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific user or role identifiers.
* Scheduled decommissioning of outdated or unused RDS instances can also result in false positives. Maintain an updated list of decommissioning schedules and exclude these from the detection rule.
* CloudFormation stack deletions that include RDS resources can lead to alerts. Monitor CloudFormation activities and correlate them with RDS deletions to differentiate between legitimate and suspicious actions.

**Response and remediation**

* Immediately isolate the affected AWS account to prevent further unauthorized actions. This can be done by revoking access keys and disabling any suspicious IAM user accounts or roles involved in the deletion.
* Initiate a recovery process for the deleted RDS instance or cluster using available backups or snapshots. Ensure that the restoration is performed in a secure environment to prevent further compromise.
* Conduct a thorough review of AWS CloudTrail logs to identify any unauthorized access patterns or anomalies leading up to the deletion event. This will help in understanding the scope of the breach and identifying potential entry points.
* Escalate the incident to the organization’s security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data were affected.
* Implement enhanced monitoring and alerting for AWS RDS and other critical resources to detect similar deletion attempts in the future. This includes setting up alerts for any unauthorized changes to IAM policies or roles.
* Review and strengthen IAM policies to ensure the principle of least privilege is enforced, reducing the risk of unauthorized deletions by limiting permissions to only those necessary for specific roles.
* Communicate with stakeholders and affected parties about the incident, outlining the steps taken for recovery and measures implemented to prevent future occurrences.


## Setup [_setup_16]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_20]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance)
and event.outcome:success
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



