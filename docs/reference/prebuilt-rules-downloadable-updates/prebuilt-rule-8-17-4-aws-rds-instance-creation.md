---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-rds-instance-creation.html
---

# AWS RDS Instance Creation [prebuilt-rule-8-17-4-aws-rds-instance-creation]

Identifies the creation of an Amazon Relational Database Service (RDS) Aurora database instance.

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

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.md)

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
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4051]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Instance Creation**

Amazon RDS simplifies database management by automating tasks like provisioning and scaling. However, adversaries may exploit this by creating unauthorized instances to exfiltrate data or establish persistence. The detection rule monitors successful RDS instance creations, focusing on specific AWS CloudTrail events, to identify potential misuse and ensure asset visibility.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.action:CreateDBInstance to gather details about the RDS instance creation, including the timestamp, user identity, and source IP address.
* Verify the user identity associated with the event to determine if the action was performed by an authorized user or service account. Check for any anomalies in user behavior or access patterns.
* Investigate the source IP address to identify if it is associated with known internal or external entities, and assess if it aligns with expected network activity.
* Examine the AWS account and region where the RDS instance was created to ensure it aligns with organizational policies and expected usage patterns.
* Check for any related events or activities in CloudTrail logs around the same timeframe, such as modifications to security groups or IAM policies, which might indicate further unauthorized actions.
* Assess the configuration and settings of the newly created RDS instance, including database engine, instance class, and network settings, to ensure they comply with security and compliance standards.

**False positive analysis**

* Routine maintenance or testing activities by authorized personnel may trigger alerts. To manage this, create exceptions for known maintenance windows or specific user accounts involved in these activities.
* Automated scripts or tools used for legitimate database provisioning can cause false positives. Identify these scripts and exclude their associated user accounts or roles from triggering alerts.
* Development or staging environments often have frequent instance creations that are non-threatening. Exclude these environments by filtering based on tags or specific resource identifiers.
* Third-party integrations or services that require RDS instance creation might be flagged. Review and whitelist these services by their IAM roles or API calls.
* Scheduled scaling operations that automatically create instances can be mistaken for unauthorized activity. Document and exclude these operations by their specific time frames or automation identifiers.

**Response and remediation**

* Immediately isolate the newly created RDS instance to prevent any unauthorized access or data exfiltration. This can be done by modifying the security group rules to restrict inbound and outbound traffic.
* Review the CloudTrail logs to identify the IAM user or role responsible for the RDS instance creation. Verify if the action was authorized and if the credentials have been compromised.
* Revoke any suspicious or unauthorized IAM credentials and rotate keys for affected users or roles to prevent further unauthorized actions.
* Conduct a thorough audit of the RDS instance configuration, including database parameters and access controls, to ensure no sensitive data has been exposed or altered.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and to determine if additional systems have been affected.
* Implement additional monitoring and alerting for unusual RDS activities, such as unexpected instance creations or modifications, to enhance detection capabilities.
* Review and update IAM policies to enforce the principle of least privilege, ensuring that only authorized users have the necessary permissions to create RDS instances.


## Setup [_setup_949]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5068]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBInstance and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



