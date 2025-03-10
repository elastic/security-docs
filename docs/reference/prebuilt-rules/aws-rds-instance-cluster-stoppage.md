---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-instance-cluster-stoppage.html
---

# AWS RDS Instance/Cluster Stoppage [aws-rds-instance-cluster-stoppage]

Identifies that an Amazon Relational Database Service (RDS) cluster or instance has been stopped.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBCluster.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-instance.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-instance.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBInstance.md)

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

## Investigation guide [_investigation_guide_72]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Instance/Cluster Stoppage**

Amazon RDS is a managed database service that simplifies database setup, operation, and scaling. Adversaries may stop RDS instances or clusters to disrupt services, potentially causing data unavailability or loss. The detection rule monitors AWS CloudTrail logs for successful stop actions on RDS resources, alerting analysts to potential unauthorized disruptions aligned with impact tactics.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the StopDBCluster or StopDBInstance action to determine if the action was authorized.
* Check the event time and correlate it with any scheduled maintenance or known operational activities to rule out legitimate stoppage.
* Investigate the source IP address and location from which the stop action was initiated to identify any anomalies or unauthorized access.
* Examine the AWS IAM policies and permissions associated with the user or role to ensure they align with the principle of least privilege.
* Look for any related alerts or logs around the same timeframe that might indicate a broader security incident or unauthorized access attempt.
* Contact the relevant database or application owner to confirm whether the stoppage was planned or expected.

**False positive analysis**

* Routine maintenance activities may trigger stop actions on RDS instances or clusters. To manage this, create exceptions for scheduled maintenance windows by excluding events occurring during these times.
* Development and testing environments often involve frequent stopping and starting of RDS instances. Identify and exclude these environments from alerts by using tags or specific instance identifiers.
* Automated scripts or tools used for cost-saving measures might stop RDS instances during off-peak hours. Review and whitelist these scripts by verifying their source and purpose.
* User-initiated stop actions for legitimate reasons, such as troubleshooting or configuration changes, can be excluded by maintaining a list of authorized personnel and their activities.
* CloudFormation or other infrastructure-as-code tools may stop RDS instances as part of deployment processes. Exclude these actions by identifying and filtering events associated with these tools.

**Response and remediation**

* Immediately verify the legitimacy of the stop action by reviewing the associated CloudTrail logs, focusing on the user identity, source IP, and time of the event to determine if the action was authorized.
* If unauthorized, isolate the affected RDS instance or cluster by disabling any associated IAM user or role that performed the stop action to prevent further unauthorized access.
* Restore the RDS instance or cluster from the latest backup or snapshot to minimize data unavailability and ensure service continuity.
* Conduct a root cause analysis to identify how the unauthorized stop action was executed, focusing on potential security gaps in IAM policies or network configurations.
* Implement additional security measures, such as enabling multi-factor authentication (MFA) for all IAM users and roles with permissions to stop RDS instances or clusters.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data were impacted.
* Update the incident response plan to include lessons learned from this event, ensuring quicker and more effective responses to similar threats in the future.


## Setup [_setup_40]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_76]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(StopDBCluster or StopDBInstance) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



