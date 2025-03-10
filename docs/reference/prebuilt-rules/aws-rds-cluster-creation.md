---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-cluster-creation.html
---

# AWS RDS Cluster Creation [aws-rds-cluster-creation]

Identifies the creation of a new Amazon Relational Database Service (RDS) Aurora DB cluster or global database spread across multiple regions.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-db-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-db-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-global-cluster.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/create-global-cluster.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateGlobalCluster.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateGlobalCluster.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Use Case: Asset Visibility
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_65]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Cluster Creation**

Amazon RDS facilitates database management by automating tasks like hardware provisioning and backups. Adversaries may exploit RDS by creating unauthorized clusters to exfiltrate data or establish persistence. The detection rule monitors successful creation events of RDS clusters, flagging potential misuse by correlating specific actions and outcomes, thus aiding in identifying unauthorized activities.

**Possible investigation steps**

* Review the event details in AWS CloudTrail to confirm the event.dataset is *aws.cloudtrail* and the event.provider is *rds.amazonaws.com*, ensuring the alert is based on the correct data source.
* Verify the identity of the user or service account that initiated the CreateDBCluster or CreateGlobalCluster action by examining the user identity information in the event logs.
* Check the event time and correlate it with any other suspicious activities or alerts in the same timeframe to identify potential patterns or coordinated actions.
* Investigate the source IP address and geolocation associated with the event to determine if it aligns with expected access patterns or if it indicates unauthorized access.
* Assess the configuration and settings of the newly created RDS cluster, including security groups, network settings, and any associated IAM roles, to identify potential security misconfigurations or vulnerabilities.
* Review the AWS account’s recent activity for any other unusual or unauthorized actions that might indicate broader compromise or misuse.

**False positive analysis**

* Routine maintenance or testing activities by authorized personnel can trigger alerts. To manage this, create exceptions for specific user accounts or roles known to perform these tasks regularly.
* Automated scripts or tools used for infrastructure management might create RDS clusters as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific tags or identifiers.
* Scheduled deployments or updates that involve creating new RDS clusters can be mistaken for unauthorized activity. Document these schedules and configure the detection rule to ignore events during these timeframes.
* Development or staging environments often involve frequent creation and deletion of RDS clusters. Exclude these environments from monitoring by filtering based on environment-specific tags or naming conventions.
* Partner or third-party integrations that require creating RDS clusters should be reviewed and whitelisted if deemed non-threatening, ensuring that their actions do not generate false positives.

**Response and remediation**

* Immediately isolate the newly created RDS cluster to prevent any unauthorized access or data exfiltration. This can be done by modifying the security group rules to restrict inbound and outbound traffic.
* Review CloudTrail logs to identify the IAM user or role responsible for the creation of the RDS cluster. Verify if the action was authorized and if the credentials have been compromised.
* Revoke any suspicious or unauthorized IAM credentials and rotate keys for affected users or roles to prevent further unauthorized actions.
* Conduct a thorough audit of the RDS cluster configuration and data to assess any potential data exposure or integrity issues. If sensitive data is involved, consider notifying relevant stakeholders and following data breach protocols.
* Implement additional monitoring and alerting for RDS-related activities, focusing on unusual patterns or actions that align with persistence tactics, to enhance detection capabilities.
* Escalate the incident to the security operations team for further investigation and to determine if additional containment or remediation actions are necessary.
* Review and update IAM policies and permissions to ensure the principle of least privilege is enforced, reducing the risk of unauthorized RDS cluster creation in the future.


## Setup [_setup_38]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_68]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(CreateDBCluster or CreateGlobalCluster) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



